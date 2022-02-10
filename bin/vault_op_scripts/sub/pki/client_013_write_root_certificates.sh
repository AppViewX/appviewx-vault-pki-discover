for i in {1..10}
do
/data/SOFTWARES/hashicorpVault/vault write pki-$i/root/generate/internal common_name=my-website.com ttl=8760h
done
