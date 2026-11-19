FROM alpine:latest
RUN apk add --no-cache nginx
COPY nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /srv/www && echo '<h1>shop</h1>' > /srv/www/index.html && echo ok > /srv/www/health
CMD ["nginx", "-g", "daemon off;"]
