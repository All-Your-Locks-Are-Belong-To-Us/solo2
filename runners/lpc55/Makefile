BOARD ?= lpcxpresso55
DEVELOP := --features board-$(BOARD),develop
DEV_PROVISIONER := --features board-$(BOARD),develop-provisioner
PROVISIONER := --features board-$(BOARD),board-provisioner

# builds firmware bundle with development features,
# i.e., no encrypted storage, etc.
.PHONY: build-dev
build-dev:
	cargo build --release $(DEVELOP)
	cargo objcopy --release $(DEVELOP) -- -O binary app.bin

# builds firmware bundle as before, *including* provisioner app
.PHONY: build-dev-provisioner
build-dev-provisioner:
	cargo build --release $(DEV_PROVISIONER)
	cargo objcopy --release $(DEV_PROVISIONER) -- -O binary provisioner.bin

# builds firmware bundle, *including* provisioner app, with some dev features disabled
.PHONY: build-provisioner
build-provisioner:
	cargo build --release $(PROVISIONER)
	cargo objcopy --release $(PROVISIONER) -- -O binary provisioner.bin

.PHONY: run-dev
run-dev:
	cargo run --release $(DEVELOP)

.PHONY: run-pro
run-pro:
	cargo run --release $(PROVISIONER)

.PHONY: bacon
bacon:
	bacon

.PHONY: jlink
jlink:
	../../scripts/bump-jlink
	JLinkGDBServer -strict -device LPC55S69 -if SWD -vd

.PHONY: clean
clean:
	cargo clean
	$(RM) app.bin provisioner.bin memory.x

PACK_VERSION := $(shell wget -O - -qq https://mcuxpresso.nxp.com/cmsis_pack/repo/NXP.pidx|grep LPC55S69|python -c'import sys; print(sys.stdin.read().rsplit("version=\"", 1)[1].split("\"", 1)[0])')
PACK := NXP.LPC55S69_DFP.$(PACK_VERSION).pack
get-cmsis-pack:
	wget -qq https://mcuxpresso.nxp.com/cmsis_pack/repo/$(PACK) -O ./lpc55s69.pack

