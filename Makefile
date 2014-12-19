all:
	@$(MAKE) -s -C ribs2          # make ribs2 first
	@echo "[server] build"
	@$(MAKE) -s -C server/src
clean:
	@$(MAKE) -s -C ribs2 clean    # clean ribs2
	@echo "[server] clean"
	@$(MAKE) -s -C server/src clean
