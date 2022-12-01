compile:
	go build -o ./bin/tug .

# this is specific to my custom PATH so that I don't have to actually run these commands
# and can lazily do make install
install:
	rm ~/.local/bin/tug
	cp ./bin/tug ~/.local/bin/tug
