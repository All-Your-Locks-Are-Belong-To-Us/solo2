RUNNER := runners/lpc55

.PHONY: build-dev
build-dev:
	make -C $(RUNNER) build-dev

.PHONY: build-dev-provisioner
build-dev-provisioner:
	make -C $(RUNNER) build-dev-provisioner

.PHONY: build-provisioner
build-provisioner:
	make -C $(RUNNER) build-provisioner

.PHONY: clean
clean:
	make -C $(RUNNER) clean

.PHONY: bacon
bacon:
	make -C $(RUNNER) bacon

.PHONY: run-dev
run-dev:
	make -C $(RUNNER) run-dev

.PHONY: jlink
jlink:
	scripts/bump-jlink
	JLinkGDBServer -strict -device LPC55S69 -if SWD -vd

.PHONY: mount-fs
mount-fs:
	scripts/fuse-bee

.PHONY: umount-fs
umount-fs:
	scripts/defuse-bee
