header_files=$(shell find elements/ | grep ".*\.hh" | sed 's/elements/click-2.0.1\/elements\/local/')
source_files=$(shell find elements/ | grep ".*\.cc" | sed 's/elements/click-2.0.1\/elements\/local/')

all: $(header_files) $(source_files)
	make -C click-2.0.1 elemlist
	make -C click-2.0.1

clean:
	rm -rf $(header_files)
	rm -rf $(source_files)

$(source_files): click-2.0.1/elements/local/%.cc: elements/%.cc
	cp $< $@

$(header_files): click-2.0.1/elements/local/%.hh: elements/%.hh
	cp $< $@