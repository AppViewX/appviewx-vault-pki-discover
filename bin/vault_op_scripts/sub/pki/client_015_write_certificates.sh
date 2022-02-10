
for i in {1..10}
do
	for j in {1..10}
	do
	 	/data/SOFTWARES/hashicorpVault/vault write pki-$i/issue/example-dot-com common_name=www$j.my-website.com ttl=8760h
	done
done
