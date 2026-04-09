Backend:
python DimyServer.py 0.0.0.0 55000 --min-common-bits 3

Frontend:
python Dimy.py 15 3 5 30 127.0.0.1 55000 --node-id N1
python Dimy.py 15 3 5 30 127.0.0.1 55000 --node-id N2
python Dimy.py 15 3 5 30 127.0.0.1 55000 --node-id N3
