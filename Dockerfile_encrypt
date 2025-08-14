FROM ubuntu:22.04

# התקנות נדרשות
RUN apt update && apt install -y \
    build-essential \
    libpthread-stubs0-dev \
    syslog-ng \
    nano \
    gcc \
    make
RUN apt update && apt install -y \
    build-essential \
    libpthread-stubs0-dev \
    libssl-dev \
    gcc \
    make

# העתקת קבצי מקור
WORKDIR /app
COPY encrypter.c .
COPY mta_crypt.c .
COPY mta_rand.c .
COPY mta_crypt.h .
COPY mta_rand.h .
COPY Makefile .

# קומפילציה
RUN make encrypter

# יצירת תיקיית לוגים
RUN mkdir -p /var/log

# נקודת כניסה
CMD ["/app/encrypter"]

