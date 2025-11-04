#!/bin/bash

# Se passo un argomento uso quello, altrimenti metto un messaggio di default
if [ -n "$1" ]; then
    COMMIT_MSG="$1"
else
    COMMIT_MSG="push automatico"
fi

# Aggiungo la parte di build e upload delle immagini custom create per il progetto.
# Le parti sono n3iwfCustom, amfCustom e smfCustom.

docker build -t zhria/n3iwfcustom:latest -f ./n3iwfCustom/Dockerfile .
docker build -t zhria/amfcustom:latest -f ./amfCustom/Dockerfile .
docker build -t zhria/smfcustom:latest -f ./smfCustom/Dockerfile .

docker push zhria/n3iwfcustom:latest
docker push zhria/amfcustom:latest
docker push zhria/smfcustom:latest

git add .
git commit -m "$COMMIT_MSG"
git push
