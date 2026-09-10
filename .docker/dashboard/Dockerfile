FROM nginx:1.29-alpine
COPY services/dashboard/index.html /usr/share/nginx/html/index.html
COPY .docker/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3003
