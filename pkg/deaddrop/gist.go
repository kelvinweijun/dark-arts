package deaddrop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

type Gist struct {
	token   string
	baseURL string
	client  *http.Client
	mu      sync.Mutex
	ids     map[string]string
}

func NewGist(token string) *Gist {
	return &Gist{
		token:   token,
		baseURL: "https://api.github.com",
		client:  &http.Client{},
		ids:     make(map[string]string),
	}
}

func (g *Gist) WithBaseURL(base string) *Gist {
	g.baseURL = base
	return g
}

type gistReq struct {
	Description string              `json:"description"`
	Public      bool                `json:"public"`
	Files       map[string]gistFile `json:"files"`
}

type gistFile struct {
	Content string `json:"content"`
}

type gistResp struct {
	ID    string                  `json:"id"`
	Files map[string]gistFileResp `json:"files"`
}

type gistFileResp struct {
	Content string `json:"content"`
}

func (g *Gist) auth(req *http.Request) {
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
}

func (g *Gist) Publish(ctx context.Context, ref string, payload []byte) error {
	body, err := json.Marshal(gistReq{
		Description: "dark-arts drop",
		Public:      false,
		Files:       map[string]gistFile{ref: {Content: base64.StdEncoding.EncodeToString(payload)}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+"/gists", bytes.NewReader(body))
	if err != nil {
		return err
	}
	g.auth(req)
	resp, err := g.client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("deaddrop: gist publish status %d", resp.StatusCode)
	}
	var out gistResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	g.mu.Lock()
	g.ids[ref] = out.ID
	g.mu.Unlock()
	return nil
}

func (g *Gist) Resolve(ctx context.Context, ref string) ([]byte, error) {
	g.mu.Lock()
	id, ok := g.ids[ref]
	g.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.baseURL+"/gists/"+id, nil)
	if err != nil {
		return nil, err
	}
	g.auth(req)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deaddrop: gist resolve status %d", resp.StatusCode)
	}
	var out gistResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	f, ok := out.Files[ref]
	if !ok {
		return nil, ErrNotFound
	}
	return base64.StdEncoding.DecodeString(f.Content)
}

func (g *Gist) Retire(ctx context.Context, ref string) error {
	g.mu.Lock()
	id, ok := g.ids[ref]
	if ok {
		delete(g.ids, ref)
	}
	g.mu.Unlock()
	if !ok {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, g.baseURL+"/gists/"+id, nil)
	if err != nil {
		return err
	}
	g.auth(req)
	resp, err := g.client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("deaddrop: gist retire status %d", resp.StatusCode)
	}
	return nil
}
