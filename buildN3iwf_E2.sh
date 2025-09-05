#Build di n3iwf
sudo docker build -t n3iwf_local -f ./n3iwfCustom/Dockerfile ./n3iwfCustom/;
sudo docker build -t n3iwf_local2 -f ./nf_n3iwf/Dockerfile ./nf_n3iwf/;
sudo docker compose -f dcb.yaml build;

sudo chmod +x ./es2im/build_es2im;

#Build di E2 Node
#cd ./e2sim
#./build_e2sim --clean;
#./build_e2sim;
