#!/usr/bin/env bash

# Script to verify the test keys written by pem_test.cxx

#################
# RSA keys

# The RSA command returns 0 on success

if [[ -f rsa-pub.new.pem ]]; then
	echo "rsa-pub.new.pem:"
	if openssl rsa -in rsa-pub.new.pem -pubin -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read rsa-pub.new.pem"
	fi
fi

if [[ -f rsa-pub.new.pem ]]; then
	echo "rsa-priv.new.pem:"
	if openssl rsa -in rsa-priv.new.pem -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read rsa-priv.new.pem"
	fi
fi

if [[ -f rsa-enc-priv.new.pem ]]; then
	echo "rsa-enc-priv.new.pem:"
	if openssl rsa -in rsa-enc-priv.new.pem -passin pass:test -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read rsa-enc-priv.new.pem"
	fi
fi

#################
# DSA keys

# The DSA command is broken. It returns 1 when using '-noout' option instead of 0.
# It also fails to parse keys with CRLF.

if [[ -f dsa-params.new.pem ]]; then
	echo "dsa-params.new.pem:"
	if openssl dsaparam -in dsa-params.new.pem -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read dsa-params.new.pem (maybe false)"
	fi
fi

if [[ -f dsa-pub.new.pem ]]; then
	echo "dsa-pub.new.pem:"
	if openssl dsa -in dsa-pub.new.pem -pubin -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read dsa-pub.new.pem (maybe false)"
	fi
fi

if [[ -f dsa-priv.new.pem ]]; then
	echo "dsa-priv.new.pem:"
	if openssl dsa -in dsa-priv.new.pem -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read dsa-priv.new.pem (maybe false)"
	fi
fi

if [[ -f dsa-enc-priv.new.pem ]]; then
	echo "dsa-enc-priv.new.pem:"
	if openssl dsa -in dsa-enc-priv.new.pem -passin pass:test -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read dsa-enc-priv.new.pem (maybe false)"
	fi
fi

#################
# EC keys

# The EC command returns 0 on success

if [[ -f ec-params.new.pem ]]; then
	echo "ec-params.new.pem:"
	if openssl ecparam -in ec-params.new.pem -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read ec-params.new.pem"
	fi
fi

if [[ -f ec-pub.new.pem ]]; then
	echo "ec-pub.new.pem:"
	if openssl ec -in ec-pub.new.pem -pubin -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read ec-pub.new.pem"
	fi
fi

if [[ -f ec-priv.new.pem ]]; then
	echo "ec-priv.new.pem:"
	if openssl ec -in ec-priv.new.pem -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read ec-priv.new.pem"
	fi
fi

if [[ -f ec-enc-priv.new.pem ]]; then
	echo "ec-enc-priv.new.pem:"
	if openssl ec -in ec-enc-priv.new.pem -passin pass:test -text -noout 1>/dev/null; then
		echo "  - OK"
	else
		echo "  - Failed to read ec-enc-priv.new.pem"
	fi
fi

echo "Finished testing keys written by Crypto++"
