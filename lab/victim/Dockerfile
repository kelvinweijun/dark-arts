FROM alpine:3.21
RUN apk add --no-cache busybox-extras && adduser -D -h /home/victim victim
WORKDIR /srv
COPY lab/victim/index.html /srv/www/index.html
USER victim
EXPOSE 8080
CMD ["httpd", "-f", "-p", "8080", "-h", "/srv/www"]
