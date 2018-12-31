# Set your own cryptopp directory, with library compiled
CRYPTOPPDIR	= ../cryptopp

INCFLAGS		= -I$(CRYPTOPPDIR)
BUILDDIR		= binary_nosave
CXX					= g++
CXXFLAGS		= -g
AR					= ar
ARFLAGS			= rcs
LIBOBJS			= $(BUILDDIR)/pem-com.o		\
							$(BUILDDIR)/pem-rd.o		\
							$(BUILDDIR)/pem-wr.o

all: pem-test.exe

pem-test.exe: $(BUILDDIR)/pem-test.o cryptopppem.a $(CRYPTOPPDIR)/libcryptopp.a
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/pem-test.o: pem-test.cxx $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(INCFLAGS)

cryptopppem.a: $(LIBOBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILDDIR)/%.o: %.cpp $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(INCFLAGS)

clean:
	rm -fr $(BUILDDIR) pem-test.exe cryptopppem.a
