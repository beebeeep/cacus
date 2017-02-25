FROM python:2.7

COPY setup.py /tmp/cacus/setup.py
COPY cacus /tmp/cacus/cacus
COPY contrib /tmp/cacus/contrib
COPY plugins /tmp/cacus/plugins

RUN cd /tmp/cacus && python setup.py install
RUN mkdir -p /opt/cacus/plugins

ARG STORAGE=file
RUN if [ $STORAGE = 'file' ] ; then cp -a /tmp/cacus/plugins/FileStorage /opt/cacus/plugins/; fi
RUN if [ $STORAGE = 'azure' ] ; then cp -a /tmp/cacus/plugins/AzureStorage /opt/cacus/plugins; pip install chardet azure-common azure-storage; fi

RUN rm -rf /tmp/cacus

EXPOSE 1488

ENTRYPOINT ["cacus", "-c", "/cacus/config.yml"]
