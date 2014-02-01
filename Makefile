#
# Set target and sources and overrides
#

TARGET := iudp
SRCS := iudp.c

LFLAGS += -lpthread

all: $(TARGET)

OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	gcc  -o $(TARGET) $^ $(LFLAGS)

install:
	install -d $(DESTDIR)/usr/bin/
	install $(TARGET)  $(DESTDIR)/usr/bin/

clean:
	rm -f $(TARGET) $(OBJS)
