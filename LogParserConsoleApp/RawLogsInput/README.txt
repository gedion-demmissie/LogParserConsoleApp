===========================================================================
    The Berndt Group -- Developer Candidate Preliminary Screening v1.8
===========================================================================

Write a program that creates a CSV report based on the provided log file.

The program should count the number of requests made by the IP addresses
contained in the log file.  The report should only count GET requests made
over the standard port used for HTTP and should exclude from the count all
requests made from IP's beginning with '207.114'.  The first field of the
report should contain the number of requests and the second field should
contain the IP address that made them.  The report should be ordered so
that IPs that made the most requests are listed first.  IPs that made the
same number of requests should be ordered amongst themselves with the IP
octets of greater values listed first.

Use the general purpose programming language in which you are most
proficient to solve the problem.

In your response, please provide the program source code, the CSV file
created by the program and how long it took for you to solve the problem.

NOTE: This screening exercise isn't representative of the type of work
developers usually do at TBG.  It's a simple test of programming ability.

EXAMPLE: Given the input:

2010-08-12 00:00:01 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /includes/scripts.js - 200 0 2258 381 94 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.mercymed.com/
2010-08-12 00:00:01 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /p7pm/p7popmenu.js - 200 0 7700 379 188 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.mercymed.com/
2010-08-12 00:00:01 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /p7pm/p6popmenu.js - 200 0 7701 379 172 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.mercymed.com/
2010-08-12 00:00:01 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /index.html - 200 0 62710 755 922 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.google.com/search?hl=en&source=hp&q=mercy+hospital+baltimore&aq=2&aqi=g10&aql=&oq=Mercy+&gs_rfai=CFJ4zGjljTI37NKDGywSzzvH-CQAAAKoEBU_QzX6b
2010-08-12 00:00:02 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /includes/js/jquery3.js - 200 0 30122 384 625 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.mercymed.com/
2010-08-12 00:00:02 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /includes/js/jqModal.js - 200 0 3604 384 109 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.mercymed.com/
2010-08-12 00:00:02 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /includes/leftflyhome.css - 200 0 4784 386 172 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.mercymed.com/
2010-08-12 00:00:03 65.37.53.228 - W3SVC106 STREAM 207.22.66.152 80 GET /includes/styles.css - 304 0 164 550 0 HTTP/1.1 www.mdmercy.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1;+Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1;+SV1)+;+.NET+CLR+1.1.4322) __utma=228961600.1048689611.1281569323.1281569323.1281570979.2;+__utmb=228961600;+__utmz=228961600.1281569323.1.1.utmccn=(direct)|utmcsr=(direct)|utmcmd=(none);+__utmc=228961600 -
2010-08-12 00:00:03 65.37.53.228 - W3SVC106 STREAM 207.22.66.152 80 GET /images/home/main/layout/bgb.jpg - 304 0 163 561 0 HTTP/1.1 www.mdmercy.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1;+Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1;+SV1)+;+.NET+CLR+1.1.4322) __utma=228961600.1048689611.1281569323.1281569323.1281570979.2;+__utmb=228961600;+__utmz=228961600.1281569323.1.1.utmccn=(direct)|utmcsr=(direct)|utmcmd=(none);+__utmc=228961600 -
2010-08-12 00:00:03 65.37.53.228 - W3SVC106 STREAM 207.22.66.152 80 GET /includes/scripts.js - 304 0 164 550 0 HTTP/1.1 www.mdmercy.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1;+Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1;+SV1)+;+.NET+CLR+1.1.4322) __utma=228961600.1048689611.1281569323.1281569323.1281570979.2;+__utmb=228961600;+__utmz=228961600.1281569323.1.1.utmccn=(direct)|utmcsr=(direct)|utmcmd=(none);+__utmc=228961600 -
2010-08-12 00:00:01 169.123.6.89 - W3SVC106 STREAM 207.22.66.152 80 GET /index.html - 200 0 62710 755 922 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.google.com/search?hl=en&source=hp&q=mercy+hospital+baltimore&aq=2&aqi=g10&aql=&oq=Mercy+&gs_rfai=CFJ4zGjljTI37NKDGywSzzvH-CQAAAKoEBU_QzX6b
2010-08-12 00:00:01 169.123.16.9 - W3SVC106 STREAM 207.22.66.152 80 GET /index.html - 200 0 62710 755 922 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.google.com/search?hl=en&source=hp&q=mercy+hospital+baltimore&aq=2&aqi=g10&aql=&oq=Mercy+&gs_rfai=CFJ4zGjljTI37NKDGywSzzvH-CQAAAKoEBU_QzX6b
2010-08-12 00:00:01 169.123.16.12 - W3SVC106 STREAM 207.22.66.152 80 GET /index.html - 200 0 62710 755 922 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.google.com/search?hl=en&source=hp&q=mercy+hospital+baltimore&aq=2&aqi=g10&aql=&oq=Mercy+&gs_rfai=CFJ4zGjljTI37NKDGywSzzvH-CQAAAKoEBU_QzX6b
2010-08-12 00:00:01 169.123.16.100 - W3SVC106 STREAM 207.22.66.152 80 GET /index.html - 200 0 62710 755 922 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.google.com/search?hl=en&source=hp&q=mercy+hospital+baltimore&aq=2&aqi=g10&aql=&oq=Mercy+&gs_rfai=CFJ4zGjljTI37NKDGywSzzvH-CQAAAKoEBU_QzX6b
2010-08-12 00:00:01 69.143.116.98 - W3SVC106 STREAM 207.22.66.152 80 GET /index.html - 200 0 62710 755 922 HTTP/1.1 www.mercymed.com Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.0;+WOW64;+GoogleT5;+SLCC1;+.NET+CLR+2.0.50727;+Media+Center+PC+5.0;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30618;+.NET4.0C) - http://www.google.com/search?hl=en&source=hp&q=mercy+hospital+baltimore&aq=2&aqi=g10&aql=&oq=Mercy+&gs_rfai=CFJ4zGjljTI37NKDGywSzzvH-CQAAAKoEBU_QzX6b


The program should output a file called 'report.csv' containing the following:

8, "69.143.116.98"
3, "65.37.53.228"
1, "169.123.16.100"
1, "169.123.16.12"
1, "169.123.16.9"
1, "169.123.6.89"

