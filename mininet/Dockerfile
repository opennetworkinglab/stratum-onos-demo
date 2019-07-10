FROM opennetworking/mn-stratum

RUN install_packages screen

COPY topo.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]