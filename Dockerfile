FROM node:20-alpine3.20

WORKDIR /tmp

COPY index.js package.json package-lock.json index.html ./

EXPOSE 3000

RUN apk update && apk add --no-cache bash openssl curl iputils &&\
    chmod +x index.js &&\
    npm install

CMD ["node", "index.js"]
