FROM nginx:alpine
COPY default.conf /etc/nginx/conf.d/default.conf
WORKDIR /usr/share/nginx/html
COPY index.html advising.html styles.css theme.js portal.js ./
COPY images/ ./images/
COPY admin/ ./admin/

