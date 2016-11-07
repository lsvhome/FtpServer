using FubarDev.FtpServer.AccountManagement;
using FubarDev.FtpServer.AccountManagement.Anonymous;
using FubarDev.FtpServer.AuthTls;
using FubarDev.FtpServer.FileSystem.DotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    public class FtpCommandCollectorTests
    {
        [Fact]
        public void TestIncomplete()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = Collect(collector, "TEST");
            Assert.Equal(new FtpCommand[0], commands);
            Assert.False(collector.IsEmpty);
        }

        [Fact]
        public void TestSingleChars()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            foreach (var ch in "USER anonymous\r\n")
            {
                commands.AddRange(Collect(collector, $"{ch}"));
            }
            Assert.Equal(
                new[] {
                    new FtpCommand("USER", "anonymous"),
                },
                commands,
                new FtpCommandComparer());
        }

        [Fact]
        public void TestCompleteCarriageReturnOnly()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = Collect(collector, "TEST\r");
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestCompleteCarriageReturnWithLineFeed()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = Collect(collector, "TEST\r\n");
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestCompleteCarriageReturnWithLineFeedAtStepTwo()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TEST\r"));
            commands.AddRange(Collect(collector, "\n"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestCompleteInTwoSteps()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TES"));
            commands.AddRange(Collect(collector, "T\r\n"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestMultipleWithoutLineFeed()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TEST1\r"));
            commands.AddRange(Collect(collector, "TEST2\r\n"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST1", string.Empty),
                    new FtpCommand("TEST2", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestMultipleWithSecondIncomplete()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TEST1\rTEST2"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST1", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.False(collector.IsEmpty);
        }

        [Fact]
        public void TestMultipleWithLineFeedInStepTwo()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TEST1\r"));
            commands.AddRange(Collect(collector, "\nTEST2\r\n"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST1", string.Empty),
                    new FtpCommand("TEST2", string.Empty),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestWithArgument()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TEST 1\r"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST", "1"),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestMultipleWithArgumentWithLineFeedInStepTwo()
        {
            var collector = new FtpCommandCollector(() => Encoding.UTF8);
            var commands = new List<FtpCommand>();
            commands.AddRange(Collect(collector, "TEST 1\r"));
            commands.AddRange(Collect(collector, "\nTEST 2\r\n"));
            Assert.Equal(
                new[]
                {
                    new FtpCommand("TEST", "1"),
                    new FtpCommand("TEST", "2"),
                },
                commands,
                new FtpCommandComparer());
            Assert.True(collector.IsEmpty);
        }

        [Fact]
        public void TestStartStopServer()
        {
            string ip = "127.0.0.1";
            int port = 2023;
            string serverPath = string.Format("ftp://{0}:{1}/testfile.txt", ip, port);

            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(serverPath);

            request.KeepAlive = true;
            request.UsePassive = true;
            request.UseBinary = true;

            request.Credentials = new NetworkCredential("anonymous", "johnDoe@test.com");

            //request.Method = WebRequestMethods.Ftp.DownloadFile;
            request.Method = WebRequestMethods.Ftp.ListDirectory;
            //request.Credentials = new NetworkCredential(username, password);



            
            // Load server certificate
            //var cert = new X509Certificate2("..\TestFtpServer\test.pfx");
            //AuthTlsCommandHandler.ServerCertificate = cert;

            // Only allow anonymous login
            var membershipProvider = new AnonymousMembershipProvider(new NoValidation());

            // Use the .NET file system
            var fsProvider = new DotNetFileSystemProvider(Path.Combine(Path.GetTempPath(), "TestFtpServer"));

            // Use all commands from the FtpServer assembly and the one(s) from the AuthTls assembly
            var commandFactory = new AssemblyFtpCommandHandlerFactory(typeof(FtpServer).Assembly, typeof(AuthTlsCommandHandler).Assembly);

            // Initialize the FTP server
            //using (
            var ftpServer = new FtpServer(fsProvider, membershipProvider, ip, port, commandFactory)
            {
                DefaultEncoding = Encoding.ASCII,
            };//)
            {

                // Start the FTP server
                ftpServer.Start();
                Console.WriteLine("Please wait for 10 sec.");
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));
                //System.Net.FtpWebRequest.Create()
                {

                    // Read the file from the server & write to destination                
                    using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
                    {
                        using (Stream responseStream = response.GetResponseStream())
                        {
                            using (StreamReader reader = new StreamReader(responseStream))
                            {
                                var ret = reader.ReadToEnd();
                                Console.WriteLine(ret);
                                System.Diagnostics.Debug.WriteLine(ret);
                                //using (StreamWriter destination = new StreamWriter(new MemoryStream()))
                                //{
                                //    destination.Write(reader.ReadToEnd());
                                //    destination.Flush();
                                //}



                                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));

                                // Stop the FTP server while client is connected
                                ftpServer.Stop();
                                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(20));
                                ftpServer.Dispose();
                                ftpServer = null;
                            }
                        }
                    }
                }


            }
        }

        private IEnumerable<FtpCommand> Collect(FtpCommandCollector collector, string data)
        {
            var temp = collector.Encoding.GetBytes(data);
            return collector.Collect(temp, 0, temp.Length);
        }

        private class FtpCommandComparer : IComparer<FtpCommand>, IEqualityComparer<FtpCommand>
        {
            private static readonly StringComparer _stringComparer = StringComparer.OrdinalIgnoreCase;

            public int Compare(FtpCommand x, FtpCommand y)
            {
                if (ReferenceEquals(x, y))
                    return 0;
                if (ReferenceEquals(x, null) && !ReferenceEquals(y, null))
                    return -1;
                if (ReferenceEquals(y, null))
                    return 1;
                var v = string.Compare(x.Name, y.Name, StringComparison.OrdinalIgnoreCase);
                if (v != 0)
                    return v;
                return _stringComparer.Compare(x.Argument, y.Argument);
            }

            public bool Equals(FtpCommand x, FtpCommand y)
            {
                return Compare(x, y) == 0;
            }

            public int GetHashCode(FtpCommand obj)
            {
                return _stringComparer.GetHashCode(obj.Name)
                       ^ _stringComparer.GetHashCode(obj.Argument);
            }
        }
    }
}
