FROM ubuntu:22.04

# התקנת כלים
RUN apt update && apt install -y \
    build-essential \
    libpthread-stubs0-dev \
    gcc \
    make
RUN apt update && apt install -y \
    build-essential \
    libpthread-stubs0-dev \
    libssl-dev \
    gcc \
    make

# העתקת קבצים
WORKDIR /app
COPY decrypter.c .
COPY mta_crypt.c .
COPY mta_rand.c .
COPY mta_crypt.h .
COPY mta_rand.h .
COPY Makefile .

# קומפילציה
RUN make decrypter

# יצירת תיקיית לוגים
RUN mkdir -p /var/log

# הרצה
CMD ["/app/decrypter"]

