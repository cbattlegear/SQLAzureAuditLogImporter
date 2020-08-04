using System;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.SqlServer.XEvent.XELite;
using System.Text.Json;
using System.Linq;

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace SQLAzureAuditLogImporter
{
    class Program
    {
        //SQL Audit Blob Storage account connection string
        static string connectionString = "BlobStorageConnectionString";

        //Container name for the SQL Audit logs, defaut is sqldbauditlogs
        static string containerName = "sqldbauditlogs";

        //SQL Azure Server name (without .database.windows.net)
        static string serverName = "sqlazureservername";

        //SQL Azure database name, case sensitive
        static string databaseName = "sqlazuredatabasename";

        //Start Date of audit logs to grab (inclusive)
        static DateTime startDate = new DateTime(2020, 08, 03);

        //End date of audit logs (inclusive)
        static DateTime endDate = new DateTime(2020, 08, 04);

        // Update customerId to your Log Analytics workspace ID
        static string customerId = "WorkspaceID";

        // For sharedKey, use either the primary or the secondary Connected Sources client authentication key   
        static string sharedKey = "LogAnalyticsSharedKey";

        // LogName is name of the event type that is being submitted to Azure Monitor with have _CL appended
        static string LogName = "SQLAuditLogs";

        // Timestamp field based on SQL Audit log structure
        static string TimeStampField = "event_time";

        static async Task Main(string[] args)
        {
            // Create a BlobServiceClient object which will be used to create a container client
            BlobServiceClient blobServiceClient = new BlobServiceClient(connectionString);

            BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(containerName);

            await foreach (BlobItem blobItem in containerClient.GetBlobsAsync())
            {
                var blobNameSplit = blobItem.Name.Split("/");

                var blobDate = DateTime.Parse(blobNameSplit[3]);

                // Structure based on servername/databasename/audit_name/date/filename.xel
                if (
                    blobNameSplit[0] == serverName && 
                    blobNameSplit[1] == databaseName &&
                    blobItem.Name.EndsWith(".xel") &&
                    blobDate >= startDate &&
                    blobDate <= endDate
                    )
                {

                    Console.WriteLine("\t" + blobItem.Name);

                    //Assuming we meet all the filtering criteria, parse and output to log analytics
                    BlobClient blobClient = containerClient.GetBlobClient(blobItem.Name);

                    BlobDownloadInfo download = await blobClient.DownloadAsync();

                    string downloadFilePath = "holdinglog.xel";

                    using (FileStream downloadFileStream = File.OpenWrite(downloadFilePath))
                    {
                        await download.Content.CopyToAsync(downloadFileStream);
                        downloadFileStream.Close();
                    }

                    List<IReadOnlyDictionary<string, object>> events = new List<IReadOnlyDictionary<string, object>>();

                    XEFileEventStreamer xelreader = new XEFileEventStreamer(downloadFilePath);

                    xelreader.ReadEventStream(
                        () =>
                        {
                            return Task.CompletedTask;
                        },
                        xevent =>
                        {
                            events.Add(xevent.Fields);
                            return Task.CompletedTask;
                        },
                        CancellationToken.None).Wait();

                    string json = JsonSerializer.Serialize(events);

                    var jsonBytesSize = Encoding.UTF8.GetBytes(json).Length;

                    if (jsonBytesSize > 30000000)
                    {
                        splitAndPost(events);
                    }
                    else
                    {
                        post(json);
                    }

                    File.Delete(downloadFilePath);
                }

            }
        }

        public static void splitAndPost(List<IReadOnlyDictionary<string, object>> events)
        {
            // Quick LINQ split code from stack: https://stackoverflow.com/a/10700594/404006
            var first_events = events.Take(events.Count / 2).ToList();
            var second_events = events.Skip(events.Count / 2).ToList();

            //Start on the first chunk
            string json = JsonSerializer.Serialize(first_events);

            var jsonBytesSize = Encoding.UTF8.GetBytes(json).Length;

            if (jsonBytesSize > 30000000)
            {
                splitAndPost(first_events);
            }
            else
            {
                post(json);
            }

            //Start the second chunk
            json = JsonSerializer.Serialize(second_events);

            jsonBytesSize = Encoding.UTF8.GetBytes(json).Length;

            if (jsonBytesSize > 30000000)
            {
                splitAndPost(second_events);
            }
            else
            {
                post(json);
            }
        }

        public static void post(string json)
        {
            var datestring = DateTime.UtcNow.ToString("r");

            var jsonBytes = Encoding.UTF8.GetBytes(json);

            string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
            string hashedString = BuildSignature(stringToHash, sharedKey);
            string signature = "SharedKey " + customerId + ":" + hashedString;

            PostData(signature, datestring, json);
        }

        // Build the API signature
        public static string BuildSignature(string message, string secret)
        {
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = Convert.FromBase64String(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hash = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hash);
            }
        }

        // Send a request to the POST API endpoint
        public static void PostData(string signature, string date, string json)
        {
            try
            {
                string url = "https://" + customerId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";

                System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                client.DefaultRequestHeaders.Add("Log-Type", LogName);
                client.DefaultRequestHeaders.Add("Authorization", signature);
                client.DefaultRequestHeaders.Add("x-ms-date", date);
                client.DefaultRequestHeaders.Add("time-generated-field", TimeStampField);

                System.Net.Http.HttpContent httpContent = new StringContent(json, Encoding.UTF8);
                httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                Task<System.Net.Http.HttpResponseMessage> response = client.PostAsync(new Uri(url), httpContent);

                System.Net.Http.HttpContent responseContent = response.Result.Content;
                string result = responseContent.ReadAsStringAsync().Result;
                Console.WriteLine("Return Result: " + result);
            }
            catch (Exception excep)
            {
                Console.WriteLine("API Post Exception: " + excep.Message);
            }
        }
    }
}
