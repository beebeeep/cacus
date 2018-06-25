FROM python:3

COPY setup.py /tmp/cacus/setup.py
COPY cacus /tmp/cacus/cacus
COPY vendor /tmp/cacus/vendor
COPY contrib /tmp/cacus/contrib
COPY plugins /tmp/cacus/plugins

#ENV PYTHONPATH="/usr/lib/python2.7/dist-packages"
# python-apt in PyPi seems to be abandoned
#RUN apt-get update && apt-get -y install python-apt gnupg
#RUN pip --no-cache-dir list
RUN cd /tmp/cacus/vendor/python-jose && python setup.py install
RUN cd /tmp/cacus && python setup.py install
RUN mkdir -p /opt/cacus/plugins

ARG STORAGE=file
RUN if [ $STORAGE = 'file' ] ; then cp -a /tmp/cacus/plugins/FileStorage /opt/cacus/plugins/; fi
RUN if [ $STORAGE = 'azure' ] ; then cp -a /tmp/cacus/plugins/AzureStorage /opt/cacus/plugins; pip install chardet azure-common azure-storage; fi

RUN rm -rf /tmp/cacus

EXPOSE 1488

ENTRYPOINT ["cacus", "-c", "/cacus/config.yml"]
