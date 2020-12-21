all: ios-deploy

ios-deploy: ios-deploy.m
	gcc ios-deploy.m -o ios-deploy -F ./ -framework Foundation -framework CoreFoundation -framework MobileDevice -lcurl

clean:
	$(RM) ios-deploy