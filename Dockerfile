FROM golang:1.14-alpine3.12 as builder

RUN apk add --no-cache \
	build-base \
	curl \
	expat-dev \
	expat-static \
	fstrm-dev \
	fstrm-static \
    git \
	libevent-dev \
	libevent-static \
	linux-headers \
	musl-dev \
	openssl-dev \
	openssl-libs-static \
	perl \
	protobuf-c-dev \
	unzip \
	util-linux-dev

WORKDIR /tmp/unbound

#RUN apk --no-cache add git gcc libc-dev unbound-dev

ARG UNBOUND_VERSION=unbound-1.10.1
ARG UNBOUND_SOURCE=https://www.nlnetlabs.nl/downloads/unbound/
ARG UNBOUND_SHA1=9932931d495248b4e45d278b4679efae29238772

RUN curl -fsSL --retry 3 "${UNBOUND_SOURCE}${UNBOUND_VERSION}.tar.gz" -o unbound.tar.gz \
  && echo "${UNBOUND_SHA1}  unbound.tar.gz" | sha1sum -c - \
	&& tar xzf unbound.tar.gz --strip 1 \
	&& ./configure --with-pthreads --with-libevent \
	  --with-username= \
	  --with-chroot-dir= \
	  --with-pthreads \
	  --enable-fully-static \
	  --disable-shared \
	  --enable-event-api \
	  --enable-tfo-client \
	  --enable-tfo-server \
	  --enable-dnstap \
	  --disable-flto \
	&& make -j 4 install

WORKDIR /go/src/app
ADD . .

RUN GOOS=linux go build -installsuffix cgo -ldflags '-extldflags "-static"' -o main .

FROM scratch
COPY --from=builder /go/src/app/main /app
ENTRYPOINT ["/app"]
