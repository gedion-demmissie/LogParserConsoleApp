using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;

namespace LogParserConsoleApp
{
    /// <summary>
    /// Program class that contains the core logics modularly and the main driver method.
    /// </summary>
    class Program
    {
        private readonly static char separatorFlag = ' ';
        private readonly static char DescriptionStarterFlag = '#';
        /// <summary>
        /// Main entry method.
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            string currentDirectory = FindCurrentDirectory(new DirectoryInfo(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)));

            if (currentDirectory != null)
            {
                Console.WriteLine("Started Ingesting the Log located under \"RawLogsInput\" folder");
                var path = currentDirectory + @"\RawLogsInput\access.log";
                var contentsFromLog = ReadLogFileContent(path);
                var parsedLogToRequestsMetadata = ParseTo(contentsFromLog, separatorFlag);
                var ingestedLogs = GetNumberOfRequestsPerIpAddress(parsedLogToRequestsMetadata);
                path = currentDirectory + @"\IngestedLogResults\report.csv";
                GenerateCsvReport(ingestedLogs, path);
                Console.WriteLine("Successfully generated Csv-Report and Saved it under  IngestesLogResults folder!");
                Console.ReadKey();
            }

        }

        /// <summary>
        /// FindCurrentDirectory method.
        /// </summary>
        /// <param name="di"></param>
        /// <returns>Fully qualified name of the current Directory where this source code is residing.</returns>
        public static string FindCurrentDirectory(DirectoryInfo di)
        {
            if (di.Parent != null)
            {
                if (di.Parent.Name == nameof(LogParserConsoleApp))
                {
                    return di.Parent.FullName;
                }
                else
                {
                    return FindCurrentDirectory(di.Parent);
                }
            }
            else
            {
                return null;
            }
        }
        /// <summary>
        /// ReadLogFileContent method.
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns>list of strings parsed from the file.</returns>
        public static string[] ReadLogFileContent(string fileName)
        {
            StreamReader reader = File.OpenText(fileName); ;
            List<string> contentsInfile = new List<string>();
            string contentInaLine;

            while ((contentInaLine = reader.ReadLine()) != null)
            {
                if (!contentInaLine.StartsWith(DescriptionStarterFlag))
                {
                    contentsInfile.Add(contentInaLine);
                }
            }

            return contentsInfile.ToArray();
        }

        /// <summary>
        /// ParseTo Method.
        /// </summary>
        /// <param name="logEntries"></param>
        /// <param name="separator"></param>
        /// <returns>List of  RequestMetaData objects.</returns>
        public static List<RequestMetaData> ParseTo(string[] logEntries, char separator)
        {
            List<RequestMetaData> parsedLogEntries = new List<RequestMetaData>();
            foreach (var logEntry in logEntries)
            {
                var logFields = logEntry.Split(separator);
                if (logFields != null && logFields.Length >= 20)
                {
                    parsedLogEntries.Add(ParseToRequestMetaData(logFields));
                }
            }
            return parsedLogEntries;
        }

        /// <summary>
        /// GetNumberOfRequestsPerIpAddress method.
        /// </summary>
        /// <param name="requestsMetaData"></param>
        /// <returns>returned list of IngestedLogs.</returns>
        public static List<IngestedLog> GetNumberOfRequestsPerIpAddress(List<RequestMetaData> requestsMetaData)
        {
            return requestsMetaData.GroupBy(
                        r => r.ClientIp,
                        r => r,
                        (key, g) =>
                        new IngestedLog
                        {
                            IpAddress = key,
                            OctetRank = GetValue<ulong>(CombineOctes(key.Split('.'))),
                            Count = g.Count()
                        }).OrderByDescending(x => x.Count).ThenByDescending(x => x.OctetRank).ToList();
        }

        /// <summary>
        /// Combines the four octets.
        /// </summary>
        /// <param name="octets"></param>
        /// <returns>combined four octets.</returns>
        private static string CombineOctes(string[] octets)
        {
            string combinedOctet = string.Empty;
            for (int i = 0; i < octets.Length; i++)
            {
                if (octets[i].Length == 1)
                {
                    combinedOctet += "00" + octets[i];
                }
                else if (octets[i].Length == 2)
                {
                    combinedOctet += "0" + octets[i];
                }
                else
                {
                    combinedOctet += octets[i];
                }
            }
            return combinedOctet;
        }

        /// <summary>
        /// GenerateCsvReport method.
        /// </summary>
        /// <param name="ingestedLogs"></param>
        /// <param name="path"></param>
        public static void GenerateCsvReport(List<IngestedLog> ingestedLogs, string path)
        {
            StringBuilder csvContent = new StringBuilder();
            csvContent.AppendLine("Count,Ip-Address");
            foreach (var ingestedLog in ingestedLogs)
            {
                csvContent.AppendLine($"{ingestedLog.Count},{ingestedLog.IpAddress}");
            }
            File.WriteAllText(path, csvContent.ToString());
        }


        /// <summary>
        /// ParseToRequestMetaData method.
        /// </summary>
        /// <param name="logFields"></param>
        /// <returns>returns RequestMetaData object.</returns>
        private static RequestMetaData ParseToRequestMetaData(string[] logFields)
        {
            RequestMetaData parsedLog = new RequestMetaData { };
            if (DateTime.TryParse(string.Join(' ', new[] { logFields[0], logFields[1] }), out DateTime dateTime))
            {
                parsedLog.DateTime = dateTime;
            }
            parsedLog.ClientIp = logFields[2];
            parsedLog.UserName = logFields[3];
            parsedLog.SiteName = logFields[4];
            parsedLog.ComputerName = logFields[5];
            parsedLog.ServerIp = logFields[6];
            parsedLog.Port = GetValue<int>(logFields[7]);

            parsedLog.Method = logFields[8];
            parsedLog.UriStem = logFields[9];
            parsedLog.UriQuery = logFields[10];

            parsedLog.Status = (HttpStatusCode)Enum.Parse(typeof(HttpStatusCode), logFields[11]);

            parsedLog.Win32Status = GetValue<int>(logFields[12]);
            parsedLog.Bytes = GetValue<uint>(logFields[13]);
            parsedLog.TimeTaken = GetValue<uint>(logFields[14]);

            parsedLog.Version = logFields[15];
            parsedLog.Host = logFields[16];
            parsedLog.UserAgent = logFields[17];
            parsedLog.Cookie = logFields[18];
            parsedLog.Referrer = logFields[19];

            return parsedLog;
        }

        /// <summary>
        /// GetValue<T> Generic method.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value"></param>
        /// <returns>returns converted value from the string input value.</returns>
        private static T GetValue<T>(String value)
        {
            return (T)Convert.ChangeType(value, typeof(T));
        }

    }

    /// <summary>
    /// RequestMetaData Class.
    /// </summary>
    public class RequestMetaData
    {
        /// <summary>
        /// DateTime
        /// </summary>
        public DateTime DateTime { get; set; }

        /// <summary>
        /// ClientIp
        /// </summary>
        public string ClientIp { get; set; }

        /// <summary>
        /// UserName
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// SiteName
        /// </summary>
        public string SiteName { get; set; }

        /// <summary>
        /// ComputerName
        /// </summary>
        public string ComputerName { get; set; }

        /// <summary>
        /// ServerIp
        /// </summary>
        public string ServerIp { get; set; }

        /// <summary>
        /// Port
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Method
        /// </summary>
        public string Method { get; set; }

        /// <summary>
        /// UriStem
        /// </summary>
        public string UriStem { get; set; }

        /// <summary>
        /// UriQuery
        /// </summary>
        public string UriQuery { get; set; }

        /// <summary>
        /// Status
        /// </summary>
        public HttpStatusCode Status { get; set; }

        /// <summary>
        /// Win32Status
        /// </summary>
        public int Win32Status { get; set; }

        /// <summary>
        /// Bytes
        /// </summary>
        public uint Bytes { get; set; }

        /// <summary>
        /// TimeTaken
        /// </summary>
        public uint TimeTaken { get; set; }

        /// <summary>
        /// Version
        /// </summary>
        public string Version { get; set; }

        /// <summary>
        /// Host
        /// </summary>
        public string Host { get; set; }

        /// <summary>
        /// UserAgent
        /// </summary>
        public string UserAgent { get; set; }

        /// <summary>
        /// Cookie
        /// </summary>
        public string Cookie { get; set; }

        /// <summary>
        /// Referrer
        /// </summary>
        public string Referrer { get; set; }

        /// <summary>
        /// OctetRank
        /// </summary>

    }

    /// <summary>
    /// IngestedLog Class.
    /// </summary>
    public class IngestedLog
    {
        /// <summary>
        /// IpAddress
        /// </summary>
        public string IpAddress { get; set; }

        /// <summary>
        /// Count
        /// </summary>
        public int Count { get; set; }

        /// <summary>
        /// OctetRank
        /// </summary>
        public ulong OctetRank { get; set; }
    }
}
