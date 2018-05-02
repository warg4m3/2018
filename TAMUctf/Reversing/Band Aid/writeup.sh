gdb ./e0dd79b3d9b05e80 -x gdbcmd --batch | grep -A3 result > result
sed -n 2p result | base64 -d > encrypted
sed -n 3p result | base64 -d > privatekey
echo >> privatekey
sed -n 4p result | base64 -d >> privatekey
openssl rsautl -decrypt -inkey privatekey -raw < encrypted > flag
cat flag

# clean
rm encrypted
rm privatekey
rm result
