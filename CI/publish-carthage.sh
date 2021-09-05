brew update;
brew outdated carthage || brew upgrade carthage;
carthage build --use-xcframeworks --no-skip-current;

# TODO: Should be replaced by carthage archive, when it supports xcframeworks
zip -r VirgilE3Kit.xcframework.zip Carthage/Build/VirgilE3Kit.xcframework
