mitmpeep Ꙫ
##########

A small python library with an ambitious aim of helping you write effective mitmproxy scripts with ease. The
development of the library is only driven by the simplicity of the api it exposes through which it should
be trivial to extract into from the responses, tamper the requests and visualize the differences caused by the
tampering.

Installation
~~~~~~~~~~~~

1. ``git clone https://github.com/tunnelshade/mitmpeep``
2. ``cd mitmpeep; pip install -e mitmpeep``

Example
~~~~~~~

If you ever tried checking auth implementation for an application using two different accounts, you can relate to

+ Attempting to do actions of user 1 with session of user 2.
+ Repeating the above for all the interesting endpoints.
+ Visualizing the response to check if cross talk is actually possible.

With the help of powerful ``mitmproxy`` & ``mitmpeep``, the following script will let you do the same in a much simpler
manner

.. code-block:: python

        from mitmpeep import HTTPSPeeper, Modes


        class PrivilegeEscalationPeeper(HTTPSPeeper):
            URL_FILTER_REGEX = "endpoint\?"  # A regex to filter interesting requests

            def tamper_request(self, request):
                # Identifier eases the identification part, see the output below
                request.mpeep_identifier = "Moderator"
                return(request)

            # The way you test for horizontal escalation is you try the same request with
            # a different account but similar role cookie
            def tamper_for_replay(self, request):
                cookies = request.cookies
                cookies["fancy_session"] = "a_valid_session_of_other_user"
                request.mpeep_identifier = "User"
                request.cookies = cookies
                return(request)


        def start():
            return(PrivilegeEscalationPeeper(mode=Modes.DIFFER))


The above script will enable you to

+ filter requests using ``URL_FILTER_REGEX``.
+ tamper the filtered original requests using ``tamper_request()``.
+ tamper the original request and replay using ``tamper_for_replay()``.

The library takes care of formatting and showing simple diff of the responses along with some metadata. This concise information
should be sufficient to validate if an endpoint is vulnerable to the attack you are testing for. In the following case, it is cleary
evident that the response size is almost negligible in the tampered case and the diff attests this fact by showing that all we get is
an error in the response.::

        =================================================== Tamper N Replay ====================================================

        Moderator : Request(POST host.com/oracle/endpoint?r=2&Feed.getModel=1) -> Response(200 OK, application/json;charset=UTF-8, 6.93k)
           User   : Request(POST host.com/oracle/endpoint?r=2&Feed.getModel=1) -> Response(200 OK, application/json;charset=UTF-8, 297b)

        ---------------------------------------------------- Response Diff -----------------------------------------------------

        - {"web-app":{"servlet":[{"servlet-name":"cofaxCDS","servlet-class":"org.cofax.cds.CDSServlet","init-param":{"configGlossary:installationAt":"Philadelphia, PA","configGlossary:adminEmail":"ksm@pobox.com","configGlossary:poweredBy":"Cofax","configGlossary:poweredByIcon":"/images/cofax.gif","configGlossary:staticPath":"/content/static","templateProcessorClass":"org.cofax.WysiwygTemplate","templateLoaderClass":"org.cofax.FilesTemplateLoader","templatePath":"templates","templateOverridePath":"","defaultListTemplate":"listTemplate.htm","defaultFileTemplate":"articleTemplate.htm","useJSP":false,"jspListTemplate":"listTemplate.jsp","jspFileTemplate":"articleTemplate.jsp","cachePackageTagsTrack":200,"cachePackageTagsStore":200,"cachePackageTagsRefresh":60,"cacheTemplatesTrack":100,"cacheTemplatesStore":50,"cacheTemplatesRefresh":15,"cachePagesTrack":200,"cachePagesStore":100,"cachePagesRefresh":10,"cachePagesDirtyRead":10,"searchEngineListTemplate":"forSearchEnginesList.htm","searchEngineFileTemplate":"forSearchEngines.htm","searchEngineRobotsDb":"WEB-INF/robots.db","useDataStore":true,"dataStoreClass":"org.cofax.SqlDataStore","redirectionClass":"org.cofax.SqlRedirection","dataStoreName":"cofax","dataStoreDriver":"com.microsoft.jdbc.sqlserver.SQLServerDriver","dataStoreUrl":"jdbc:microsoft:sqlserver://LOCALHOST:1433;DatabaseName=goon","dataStoreUser":"sa","dataStorePassword":"dataStoreTestQuery","dataStoreTestQuery":"SET NOCOUNT ON;select test='test';","dataStoreLogFile":"/usr/local/tomcat/logs/datastore.log","dataStoreInitConns":10,"dataStoreMaxConns":100,"dataStoreConnUsageLimit":100,"dataStoreLogLevel":"debug","maxUrlLength":500}},{"servlet-name":"cofaxEmail","servlet-class":"org.cofax.cds.EmailServlet","init-param":{"mailHost":"mail1","mailHostOverride":"mail2"}},{"servlet-name":"cofaxAdmin","servlet-class":"org.cofax.cds.AdminServlet"},{"servlet-name":"fileServlet","servlet-class":"org.cofax.cds.FileServlet"},{"servlet-name":"cofaxTools","servlet-class":"org.cofax.cms.CofaxToolsServlet","init-param":{"templatePath":"toolstemplates/","log":1,"logLocation":"/usr/local/tomcat/logs/CofaxTools.log","logMaxSize":"","dataLog":1,"dataLogLocation":"/usr/local/tomcat/logs/dataLog.log","dataLogMaxSize":"","removePageCache":"/content/admin/remove?cache=pages&id=","removeTemplateCache":"/content/admin/remove?cache=templates&id=","fileTransferFolder":"/usr/local/tomcat/webapps/content/fileTransferFolder","lookInContext":1,"adminGroupID":4,"betaServer":true}}],"servlet-mapping":{"cofaxCDS":"/","cofaxEmail":"/cofaxutil/aemail/*","cofaxAdmin":"/admin/*","fileServlet":"/static/*","cofaxTools":"/tools/*"},"taglib":{"taglib-uri":"cofax.tld","taglib-location":"/WEB-INF/tlds/cofax.tld"}}}
        + */{"defaultHandler":"function() {var e=new Error('[SystemErrorException from server] unknown error');e.reported=true;throw e;}", "exceptionEvent":true}/*ERROR*/

        ============================ output/host.com/oracle/65d2cc6f969698f6203d4103965b7497.diff.0 ============================

For more examples, have a look at `examples`_. Combining those examples gives you some powerful primitives. If you wish to see more
functionality, have a loot at `peeper.py`_ to see what methods can be overridden.

PS: Maybe create pip package if people use it.

.. _examples: examples/
.. _peeper.py: mitmpeep/peeper.py
