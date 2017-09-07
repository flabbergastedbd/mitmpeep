#!/usr/bib/env python
"""
The idea behind this example is to ease the process of testing privilege
escalations or typically incorrect authorization. The manual way to test
this is to repeat requests in burp and manually add a different account session's
token. With the following script not only that functionality can be automated
but you get a pretty logging as well as diff files that should give a clearer picture.

"""

from mitmpeep import HTTPSPeeper, Modes


class PrivilegeEscalationPeep(HTTPSPeeper):
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
    return(PrivilegeEscalationPeep(mode=Modes.DIFFER))

"""
This script will log
    + diff to the log file
    + the diff to a file $output_dir/<any_host>/super/oracle/<unique_hash>.diff.0

Sample Log Output

=================================================== Tamper N Replay ====================================================

Moderator : Request(POST host.com/oracle/endpoint?r=2&Feed.getModel=1) -> Response(200 OK, application/json;charset=UTF-8, 6.93k)
   User   : Request(POST host.com/oracle/endpoint?r=2&Feed.getModel=1) -> Response(200 OK, application/json;charset=UTF-8, 297b)

---------------------------------------------------- Response Diff -----------------------------------------------------

- {"web-app":{"servlet":[{"servlet-name":"cofaxCDS","servlet-class":"org.cofax.cds.CDSServlet","init-param":{"configGlossary:installationAt":"Philadelphia, PA","configGlossary:adminEmail":"ksm@pobox.com","configGlossary:poweredBy":"Cofax","configGlossary:poweredByIcon":"/images/cofax.gif","configGlossary:staticPath":"/content/static","templateProcessorClass":"org.cofax.WysiwygTemplate","templateLoaderClass":"org.cofax.FilesTemplateLoader","templatePath":"templates","templateOverridePath":"","defaultListTemplate":"listTemplate.htm","defaultFileTemplate":"articleTemplate.htm","useJSP":false,"jspListTemplate":"listTemplate.jsp","jspFileTemplate":"articleTemplate.jsp","cachePackageTagsTrack":200,"cachePackageTagsStore":200,"cachePackageTagsRefresh":60,"cacheTemplatesTrack":100,"cacheTemplatesStore":50,"cacheTemplatesRefresh":15,"cachePagesTrack":200,"cachePagesStore":100,"cachePagesRefresh":10,"cachePagesDirtyRead":10,"searchEngineListTemplate":"forSearchEnginesList.htm","searchEngineFileTemplate":"forSearchEngines.htm","searchEngineRobotsDb":"WEB-INF/robots.db","useDataStore":true,"dataStoreClass":"org.cofax.SqlDataStore","redirectionClass":"org.cofax.SqlRedirection","dataStoreName":"cofax","dataStoreDriver":"com.microsoft.jdbc.sqlserver.SQLServerDriver","dataStoreUrl":"jdbc:microsoft:sqlserver://LOCALHOST:1433;DatabaseName=goon","dataStoreUser":"sa","dataStorePassword":"dataStoreTestQuery","dataStoreTestQuery":"SET NOCOUNT ON;select test='test';","dataStoreLogFile":"/usr/local/tomcat/logs/datastore.log","dataStoreInitConns":10,"dataStoreMaxConns":100,"dataStoreConnUsageLimit":100,"dataStoreLogLevel":"debug","maxUrlLength":500}},{"servlet-name":"cofaxEmail","servlet-class":"org.cofax.cds.EmailServlet","init-param":{"mailHost":"mail1","mailHostOverride":"mail2"}},{"servlet-name":"cofaxAdmin","servlet-class":"org.cofax.cds.AdminServlet"},{"servlet-name":"fileServlet","servlet-class":"org.cofax.cds.FileServlet"},{"servlet-name":"cofaxTools","servlet-class":"org.cofax.cms.CofaxToolsServlet","init-param":{"templatePath":"toolstemplates/","log":1,"logLocation":"/usr/local/tomcat/logs/CofaxTools.log","logMaxSize":"","dataLog":1,"dataLogLocation":"/usr/local/tomcat/logs/dataLog.log","dataLogMaxSize":"","removePageCache":"/content/admin/remove?cache=pages&id=","removeTemplateCache":"/content/admin/remove?cache=templates&id=","fileTransferFolder":"/usr/local/tomcat/webapps/content/fileTransferFolder","lookInContext":1,"adminGroupID":4,"betaServer":true}}],"servlet-mapping":{"cofaxCDS":"/","cofaxEmail":"/cofaxutil/aemail/*","cofaxAdmin":"/admin/*","fileServlet":"/static/*","cofaxTools":"/tools/*"},"taglib":{"taglib-uri":"cofax.tld","taglib-location":"/WEB-INF/tlds/cofax.tld"}}}
+ */{"defaultHandler":"function() {var e=new Error('[SystemErrorException from server] unknown error');e.reported=true;throw e;}", "exceptionEvent":true}/*ERROR*/

============================ output/host.com/oracle/65d2cc6f969698f6203d4103965b7497.diff.0 ============================

"""
