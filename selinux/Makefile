POLICY = rustnet

all: $(POLICY).pp

$(POLICY).pp: $(POLICY).te $(POLICY).fc
	$(MAKE) -f /usr/share/selinux/devel/Makefile $(POLICY).pp

clean:
	rm -f $(POLICY).pp $(POLICY).mod $(POLICY).tmp
	rm -rf tmp

.PHONY: all clean
