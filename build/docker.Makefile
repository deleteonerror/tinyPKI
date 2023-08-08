.PHONY: docker-arm

docker-arm: docker-arm-root docker-arm-sub

docker-arm-root:
	docker buildx build \
	--platform linux/arm64 \
	-t tpkiroot:local -f build/Dockerfile-tpkiroot  . --load

docker-arm-sub:
	docker buildx build \
	--platform linux/arm64 \
	-t tpkisub:local -f build/Dockerfile-tpkisub  . --load
