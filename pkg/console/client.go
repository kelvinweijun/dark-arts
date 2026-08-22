package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dark-arts/pkg/server"
	"dark-arts/pkg/tasking"
	"dark-arts/pkg/ttp"
	"golang.org/x/net/websocket"
)

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("console: %s %s: %s", method, path, resp.Status)
	}
	return out, nil
}

func (c *Client) Health(ctx context.Context) (bool, error) {
	_, err := c.request(ctx, http.MethodGet, "/healthz", nil)
	return err == nil, err
}

func (c *Client) Sessions(ctx context.Context) ([]server.Session, error) {
	out, err := c.request(ctx, http.MethodGet, "/api/v1/sessions", nil)
	if err != nil {
		return nil, err
	}
	var s []server.Session
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, err
	}
	return s, nil
}

func (c *Client) Session(ctx context.Context, id string) (*server.Session, error) {
	out, err := c.request(ctx, http.MethodGet, "/api/v1/sessions/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var s server.Session
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) DeleteSession(ctx context.Context, id string) error {
	_, err := c.request(ctx, http.MethodDelete, "/api/v1/sessions/"+url.PathEscape(id), nil)
	return err
}

func (c *Client) Touch(ctx context.Context, id, agentPubHex string) error {
	_, err := c.request(ctx, http.MethodPost, "/api/v1/sessions", map[string]string{
		"id": id, "agent_pub": agentPubHex,
	})
	return err
}

func (c *Client) IssueTask(ctx context.Context, sid, opID, typ string, params map[string]string, signedBy string) (*tasking.Task, error) {
	out, err := c.request(ctx, http.MethodPost, "/api/v1/tasks", map[string]any{
		"session_id": sid, "op_id": opID, "type": typ, "params": params, "signed_by": signedBy,
	})
	if err != nil {
		return nil, err
	}
	var t tasking.Task
	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (c *Client) Tasks(ctx context.Context) ([]tasking.Task, error) {
	out, err := c.request(ctx, http.MethodGet, "/api/v1/tasks", nil)
	if err != nil {
		return nil, err
	}
	var t []tasking.Task
	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}
	return t, nil
}

func (c *Client) Results(ctx context.Context) ([]tasking.Result, error) {
	out, err := c.request(ctx, http.MethodGet, "/api/v1/results", nil)
	if err != nil {
		return nil, err
	}
	var r []tasking.Result
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Client) TTPs(ctx context.Context) ([]*ttp.Spec, error) {
	out, err := c.request(ctx, http.MethodGet, "/api/v1/ttps", nil)
	if err != nil {
		return nil, err
	}
	var specs []*ttp.Spec
	if err := json.Unmarshal(out, &specs); err != nil {
		return nil, err
	}
	return specs, nil
}

func (c *Client) Watch(ctx context.Context, onEvent func(server.Event) error) error {
	u := c.baseURL + "/api/v1/ws"
	if strings.HasPrefix(u, "https://") {
		u = "wss://" + strings.TrimPrefix(u, "https://")
	} else {
		u = "ws://" + strings.TrimPrefix(u, "http://")
	}
	cfg, err := websocket.NewConfig(u, c.baseURL)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		cfg.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		return err
	}
	defer ws.Close()
	go func() {
		<-ctx.Done()
		ws.Close()
	}()
	for {
		var ev server.Event
		if err := websocket.JSON.Receive(ws, &ev); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if err := onEvent(ev); err != nil {
			return err
		}
	}
}

var errServer = errors.New("console: server unreachable")

func IsServerErr(err error) bool {
	var u *url.Error
	if errors.As(err, &u) {
		return true
	}
	return strings.Contains(err.Error(), "server unreachable")
}
