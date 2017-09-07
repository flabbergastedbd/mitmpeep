.PHONY: test

test:
	coverage run --source mitmpeep/ -m unittest discover -s tests/
	coverage report -m
