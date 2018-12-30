# Set your own cryptopp directory, with library compiled
CRYPTOPPDIR	= ../cryptopp

INCFLAGS		= -I$(CRYPTOPPDIR)
EXECUTABLE	= pem-test.exe
BUILDDIR		= binary_nosave
CC					= g++
CFLAGS			= -g -c
OBJECTS			= $(BUILDDIR)/pem-com.o		\
							$(BUILDDIR)/pem-rd.o		\
							$(BUILDDIR)/pem-wr.o

all: $(EXECUTABLE)

$(EXECUTABLE): $(BUILDDIR) $(BUILDDIR)/pem-test.o $(OBJECTS) $(CRYPTOPPDIR)/libcryptopp.a
	$(CC) -o $@ $(BUILDDIR)/pem-test.o $(OBJECTS) $(CRYPTOPPDIR)/libcryptopp.a

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/pem-test.o: $(BUILDDIR)
	$(CC) $(CFLAGS) pem-test.cxx -o $@ $(INCFLAGS)

$(BUILDDIR)/%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@ $(INCFLAGS)

clean:
	rm -fr $(BUILDDIR) $(EXECUTABLE)
