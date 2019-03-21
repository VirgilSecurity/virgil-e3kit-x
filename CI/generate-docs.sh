gem install jazzy

jazzy \
--author "Virgil Security" \
--author_url "https://virgilsecurity.com/" \
--xcodebuild-arguments -scheme,"VirgilE3Kit macOS" \
--module "VirgilE3kit" \
--output "${OUTPUT}" \
--hide-documentation-coverage \
--theme apple
