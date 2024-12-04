///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// (c) NFON AG 2023
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
// LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Net;
using System.IO;
using System.Text.Json.Serialization;

namespace PSDS
{
   class Program
   {
      /// <summary>
      /// Global variable for the username
      /// </summary>
      private string Username { get; set; }
      /// <summary>
      /// Global variable for the password
      /// </summary>
      private string Password { get; set; }
      /// <summary>
      /// The current access token (set after the first login)
      /// </summary>
      private string AccessToken { get; set; }
      /// <summary>
      /// The current refresh token (set after the first login)
      /// </summary>
      private string RefreshToken { get; set; }
      /// <summary>
      /// The PBX for the access token (parsed out of the token)
      /// </summary>
      private string PBX { get; set; }
      /// <summary>
      /// The expiration time of the access token (parsed out of the token)
      /// </summary>
      private long Expiration { get; set; }
      /// <summary>
      /// If the access token allows the usage of extended presence (mandatory for the usage)
      /// </summary>
      private bool ExtendedPresence { get; set; }
      /// <summary>
      /// The unique ID of the last initiated call
      /// </summary>
      private string LastCallUUID { get; set; }
      /// <summary>
      /// The latest state of the last initiated call
      /// </summary>
      private string LastCallState { get; set; }
      
      public static string URL = "https://providersupportdata.cloud-cfg.com/v1";

      static void Main()
      {
         Program program = new Program();
         program.Run();
      }

      private void Run()
      {
         QueryCredentials();
         ShowMenu();
      }

      private void ShowMenu()
      {
         bool isFirstMenu = true;
         int menu = 0;
         while (true)
         {
            while (!(menu >= 1 && menu <= 4))
            {
               Console.WriteLine();
               if (isFirstMenu)
               {
                  Console.WriteLine("----------------------------------------");
                  Console.WriteLine(@"   \               ___  __       ");
                  Console.WriteLine(@"  /\\    /  |\  | |    /  \ |\  |");
                  Console.WriteLine(@" /  \\  /   | \ | |--  |  | | \ |");
                  Console.WriteLine(@"/    \\/    |  \| |    \__/ |  \|");
                  Console.WriteLine(@"      \                          ");
                  isFirstMenu = false;
               }
               Console.WriteLine("----------------------------------------");
               Console.WriteLine(string.Format("Connected to {0}", PBX));
               Console.WriteLine("Main menu:");
               Console.WriteLine("----------------------------------------");
               Console.WriteLine("1. extension data");
               Console.WriteLine("2. status event stream - COMMING SOON");
               Console.WriteLine("3. calls event stream");
               Console.WriteLine("4. initiate call");
               Console.WriteLine("----------------------------------------");
               Console.Write("Choose 1-4: ");
               string selection = Console.ReadLine();
               if (string.IsNullOrWhiteSpace(selection))
               {
                  return;
               }
               int.TryParse(selection, out menu);
               if (menu >= 1 && menu <= 4)
               {
                  Console.WriteLine();
               }
            }
            switch (menu)
            {
               case 1:
                  ReadExtensions();
                  break;
               //case 2:
               //   OpenStatusEventStream();
               //   break;
               case 3:
                  OpenCallEventStream();
                  break;
               case 4:
                  InitCallMenu();
                  break;
            }
            menu = 0;
         }
      }

      private void QueryCredentials()
      {
         bool loggedIn = false;
         while (!loggedIn)
         {
            Console.Write("Enter your username: ");
            Username = Console.ReadLine();
            Console.Write("Enter your password: ");
            Password = ReadPassword();

            if (Password != null)
            {
               loggedIn = Login();
               if (loggedIn)
               {
                  if (!ExtendedPresence)
                  {
                     Console.WriteLine("Your API key does not allow extended presence, several functions are not available. This type of key is currently not supported in the Test App!");
                     loggedIn = false;
                  }
                  else
                  {
                     Console.Clear();
                     return;
                  }
               }
               else
               {
                  Console.WriteLine("Sorry, the login did not work, please try again.");
               }
            }
         }
      }

      /// <summary>
      /// Reads a password and masking the characters with asterisks
      /// </summary>
      /// <returns>The entered password or null when interrupted</returns>
      private string ReadPassword()
      {
         var pass = string.Empty;
         ConsoleKey key;
         do
         {
            var keyInfo = Console.ReadKey(intercept: true);
            key = keyInfo.Key;

            if (key == ConsoleKey.Backspace && pass.Length > 0)
            {
               Console.Write("\b \b");
               pass = pass.Remove(pass.Length - 1);
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
               Console.Write("*");
               pass += keyInfo.KeyChar;
            }
         } while (key != ConsoleKey.Enter && key != ConsoleKey.Escape);
         Console.WriteLine();
         if (key == ConsoleKey.Escape)
         {
            return null;
         }

         return pass;
      }

      /// <summary>
      /// Sends the login request and parses the returned token
      /// </summary>
      /// <returns>true if the login was successful, otherwise false</returns>
      private bool Login()
      {
         LoginRequestModel data = new LoginRequestModel
         {
            Username = Username,
            Password = Password
         };
         string response = SendRequest("POST", "/login", JsonSerializer.Serialize(data), false);
         if (!string.IsNullOrWhiteSpace(response))
         {
            LoginResponseModel loginResponse = JsonSerializer.Deserialize<LoginResponseModel>(response);
            AccessToken = loginResponse.AccessToken;
            RefreshToken = loginResponse.RefreshToken;
            ParseAccessToken();

            return true;
         }
         return false;
      }

      /// <summary>
      /// Parses the retuned JWT token to get the PBX, the expiration timestamp of the token and if extended presence is allowed for the token.
      /// </summary>
      private void ParseAccessToken()
      {
         if (AccessToken.Split('.').Length == 3)
         {
            string payloadString = AccessToken.Split('.')[1];
            payloadString = payloadString.PadRight(payloadString.Length + (4 - payloadString.Length % 4) % 4, '=');

            JWTPayloadModel payload = JsonSerializer.Deserialize<JWTPayloadModel>(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(payloadString)));
            PBX = payload.Customer;
            Expiration = payload.Expiration;
            ExtendedPresence = payload.ExtendedPresence;
         }
      }

      /// <summary>
      /// Check if the token needs a refresh
      /// </summary>
      private void CheckAccessToken()
      {
         if(Expiration - 10 < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
         {
            RefreshAccessToken();
         }
      }

      /// <summary>
      /// Refresh the token (tokens exipre after 5 minutes and need to be refreshed)
      /// </summary>
      /// <returns>true if the token refresh was successfull</returns>
      private bool RefreshAccessToken()
      {
         Console.WriteLine("Refreshing access token");
         string response = SendRequest("PUT", "/login", "", true, RefreshToken);
         if (!string.IsNullOrWhiteSpace(response))
         {
            LoginResponseModel loginResponse = JsonSerializer.Deserialize<LoginResponseModel>(response);
            AccessToken = loginResponse.AccessToken;
            RefreshToken = loginResponse.RefreshToken;
            ParseAccessToken();
            return true;
         }
         return false;
      }

      /// <summary>
      /// 2. Opens an event stream to receive status updated of extensions
      /// </summary>
      private void OpenStatusEventStream()
      {
         Console.WriteLine("Waiting for status events on the PBX (press a key to abort)...");
         CheckAccessToken();
         EventStreamServiceWrapper<PhoneStateResponseModel> wrapper = new EventStreamServiceWrapper<PhoneStateResponseModel>("/extensions/phone/states", AccessToken);
         Console.ReadKey();
         wrapper.Close();
      }

      /// <summary>
      /// 3. Opens an event stream to receive call events on the PBX
      /// </summary>
      private void OpenCallEventStream()
      {
         Console.WriteLine("Waiting for calls on the PBX (press a key to abort)...");
         CheckAccessToken();
         EventStreamServiceWrapper<PhoneCallResponseModel> wrapper = new EventStreamServiceWrapper<PhoneCallResponseModel>("/extensions/phone/calls", AccessToken);
         Console.ReadKey();
         wrapper.Close();
      }

      /// <summary>
      /// The event handler for call events received from the SSE connection
      /// </summary>
      /// <param name="sender">The sender of the event</param>
      /// <param name="o">The object containing the event data (parsed from JSON)</param>
      private void ResponseObjectCallEventReceived(object sender, ResponseModel o)
      {
         PhoneCallStatusResponseModel model = (PhoneCallStatusResponseModel)o;
         LastCallState = model.State;
         LastCallUUID = model.UUID;
      }

      /// <summary>
      /// The type of how the call is initiated
      /// </summary>
      private enum CallType
      {
         /// <summary>
         /// The call is initiated with receiving events afterwards
         /// </summary>
         EVENT = 1,
         /// <summary>
         /// The call is initiated with just one start response
         /// </summary>
         INIT = 2
      }

      /// <summary>
      /// 4. Asking for the details of the call to be initiated
      /// </summary>
      private void InitCallMenu()
      {
         Console.Write("Which extension should call (e.g. 123): ");
         string extension = Console.ReadLine();
         if (string.IsNullOrWhiteSpace(extension))
         {
            return;
         }

         Console.Write("Which target do you want to call (e.g. 00498999998123 or conference code e.g. oBKTujVniYLiU7GetWoT): ");
         string target = Console.ReadLine();
         if (string.IsNullOrWhiteSpace(target))
         {
            return;
         }

         Console.Write("Do you want to wait for events (1) or only initiate the call (2): ");
         string selection = Console.ReadLine();
         int.TryParse(selection, out int menu);
         if (menu != 1 && menu != 2)
         {
            menu = 1;
         }

         InitCall(extension, target, (CallType)menu);
      }

      /// <summary>
      /// Handling initiating the actual call
      /// </summary>
      /// <param name="extension">the extension which is initiating the call</param>
      /// <param name="target">the number to be called</param>
      /// <param name="type">the type of the call (with events or single response)</param>
      private void InitCall(string extension, string target, CallType type)
      {
         CheckAccessToken();

         CallsRequestModel model = new CallsRequestModel
         {
            Callee = target,
            CalleeContext = PBX,
            Caller = extension,
            CallerContext = PBX,
            Extension = extension
         };

         if (type == CallType.EVENT) //the call is initiated and events should be received
         {
            LastCallState = string.Empty;
            LastCallUUID = string.Empty;
            EventStreamServiceWrapper<PhoneCallStatusResponseModel> wrapper = new EventStreamServiceWrapper<PhoneCallStatusResponseModel>("/extensions/phone/calls", AccessToken, JsonSerializer.Serialize(model));
            //The event is registered to receive updates on the call (UUID and status) needed for cancelling - see below
            wrapper.ResponseObjectReceived += ResponseObjectCallEventReceived;
            Console.ReadKey();
            wrapper.Close();

            //Calls can be terminated while still ringing on the initiating extension
            //   check to make sure there is a UUID required by the DELETE method and that it is still proceeding
            if (!string.IsNullOrWhiteSpace(LastCallUUID) && (LastCallState == "start" || LastCallState == "caller-dial" || LastCallState == "caller-ring"))
            {
               Console.WriteLine("Call is still proceeding, try to cancel...");
               //sends a cancellation request for the call
               SendRequest("DELETE", string.Format("/extensions/phone/calls/{0}", LastCallUUID), JsonSerializer.Serialize(model), true);
            }
            else
            {
               Console.WriteLine("Call is answered or unknown, can't be cancelled anymore...");
            }
         }
         else if(type == CallType.INIT) //the call is initiated with just a single response
         {
            string response = SendRequest("POST", "/extensions/phone/calls", JsonSerializer.Serialize(model), true);
            response = response.Replace("data:", "");
            PhoneCallStatusResponseModel responseObject = JsonSerializer.Deserialize<PhoneCallStatusResponseModel>(response);
            Console.WriteLine(responseObject.ToString());
         }
      }

      /// <summary>
      /// This class is overwriting the WebClient class. This is needed to be able to POST data to an endpoint which is responding with an SSE stream (as this functionality does not exist in the original implementation).
      /// </summary>
      public class WebClientWithResponse : WebClient
      {
         public delegate void ResponseLineReceivedEventHandler(object sender, ResponseLineReceivedEventArgs e);

         public event ResponseLineReceivedEventHandler ResponseLineReceived;

         /// <summary>
         /// Event args for returning the stream of events
         /// </summary>
         public class ResponseLineReceivedEventArgs : System.EventArgs
         {
            public Stream Stream { get; }
            public ResponseLineReceivedEventArgs(Stream stream)
            {
               this.Stream = stream;
            }
         }

         /// <summary>
         /// Overwrites the function to pull out the response stream and publish it through the event
         /// </summary>
         /// <param name="request"></param>
         /// <returns></returns>
         protected override WebResponse GetWebResponse(WebRequest request)
         {
            var response = base.GetWebResponse(request);
            if (response is HttpWebResponse httpResponse)
            {
               ResponseLineReceived?.Invoke(this, new ResponseLineReceivedEventArgs(httpResponse.GetResponseStream()));
            }
            return response;
         }
      }

      /// <summary>
      /// A wrapper for handling requests with SSE streams using the WebClient class
      /// </summary>
      /// <typeparam name="ResponseModel">The object received as response in the SSE stream</typeparam>
      public class EventStreamServiceWrapper<ResponseModel>
      {
         public delegate void ResponseObjectReceivedEventHandler(object sender, ResponseModel o);
         public event ResponseObjectReceivedEventHandler ResponseObjectReceived;

         private bool stop = false;
         WebClient Wc { get; set; }

         public EventStreamServiceWrapper(string endpoint, string token)
         {
            Init(endpoint, token, null);
         }

         public EventStreamServiceWrapper(string endpoint, string token, string body)
         {
            Init(endpoint, token, body);
         }

         private void Init(string endpoint, string token, string body)
         {
            if (!string.IsNullOrWhiteSpace(body))
            {
               //as soon as a body is sent, the response need to be handled differently with the derived class from WebClient
               Wc = new WebClientWithResponse();
               ((WebClientWithResponse)Wc).ResponseLineReceived += ServerEventOccurs;
            }
            else
            {
               Wc = new WebClient();
            }
            Wc.Headers.Add("Accept", "text/event-stream");
            Wc.Headers.Add("Authorization", string.Format("Bearer {0}", token));
            Wc.Headers.Add("Content-Type", "application/json");
            Wc.OpenReadCompleted += ServerEventOccurs;

            if (!string.IsNullOrWhiteSpace(body))
            {
               //The async implementation of UploadString can't be used in this case, because the response stream
               //    is opened right afterwards, which would result in reading and writing on the stream at the same time
               var t = new Task(() =>
               {
                  Wc.UploadString(new Uri(Program.URL + endpoint), body);
               });
               t.Start();
            }
            else
            {
               Wc.OpenReadAsync(new Uri(Program.URL + endpoint));
            }
         }

         public void Close()
         {
            stop = true;
            Wc.CancelAsync();
         }

         /// <summary>
         /// The event handler for responses after a post
         /// </summary>
         /// <param name="sender"></param>
         /// <param name="args"></param>
         private void ServerEventOccurs(object sender, WebClientWithResponse.ResponseLineReceivedEventArgs args)
         {
            using (var sr = new StreamReader(args.Stream))
            {
               while (stop == false)
               {
                  string line = sr.ReadLine();
                  if (line != null && line.Contains("data:"))
                  {
                     HandleStatusMessage(line);
                  }
               }
            }
         }

         private async void ServerEventOccurs(object sender, OpenReadCompletedEventArgs args)
         {
            try
            {
               if (args.Error != null)
               {
                  Console.WriteLine("Error: " + args.Error.Message);
                  Close();
                  return;
               }

               using (var sr = new StreamReader(args.Result))
               {
                  while (true)
                  {
                     string line = await sr.ReadLineAsync();
                     if (line.Contains("data:"))
                     {
                        HandleStatusMessage(line);
                     }
                  }
               }
            }
            catch (Exception)
            { }
         }


         /// <summary>
         /// A JSON object prepended with "data:" is received, the JSON object is parsed and printed on the console and sent as an event
         /// </summary>
         /// <param name="line"></param>
         private void HandleStatusMessage(string line)
         {
            line = line.Replace("data:", "");
            ResponseModel model = JsonSerializer.Deserialize<ResponseModel>(line);
            Console.WriteLine(model.ToString());
            ResponseObjectReceived?.Invoke(this, model);
         }
      }

      /// <summary>
      /// 1. Reading all extensions from the PBX and printing it to the console
      /// </summary>
      private void ReadExtensions()
      {
         CheckAccessToken();
         string response = SendRequest("GET", "/extensions/phone/data", "", true);
         List<PhoneDataResponseModel> phoneDataResponse = JsonSerializer.Deserialize<List<PhoneDataResponseModel>>(response);
         foreach (PhoneDataResponseModel item in phoneDataResponse)
         {
            Console.WriteLine(item.ToString());
         }
      }

      /// <summary>
      /// Sends a request to the API endpoint
      /// </summary>
      /// <param name="method">The method of the request</param>
      /// <param name="endpoint">The endpoint of the request (not containing the full domain)</param>
      /// <param name="content">The body sent in the request (or empty if no body should be sent)</param>
      /// <param name="authorize">If this request needs to be authorized with the API Token</param>
      /// <returns>The response from the server</returns>
      private string SendRequest(string method, string endpoint, string content, bool authorize)
      {
         return SendRequest(method, endpoint, content, authorize, AccessToken);
      }

      /// <summary>
      /// Sends a request to the API endpoint
      /// </summary>
      /// <param name="method">The method of the request</param>
      /// <param name="endpoint">The endpoint of the request (not containing the full domain)</param>
      /// <param name="content">The body sent in the request (or empty if no body should be sent)</param>
      /// <param name="authorize">If this request needs to be authorized with the API Token</param>
      /// <param name="token">The token for the request (when refreshing the token, then the separate refresh token needs to be sent)</param>
      /// <returns>The response from the server</returns>
      private string SendRequest(string method, string endpoint, string content, bool authorize, string token)
      {
         try
         {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

            string fullUrl = Program.URL + endpoint;
            string response;

            var request = (HttpWebRequest)WebRequest.Create(fullUrl);

            request.Method = method;
            request.ContentType = "application/json";
            request.Accept = "*/*";
            if (authorize)
            {
               request.Headers.Add("Authorization", string.Format("Bearer {0}", token));
            }

            if (!string.IsNullOrWhiteSpace(content))
            {
               using (Stream stream = request.GetRequestStream())
               {
                  byte[] data = Encoding.UTF8.GetBytes(content);
                  stream.Write(data, 0, data.Length);
               }
            }

            using (var responseO = (HttpWebResponse)request.GetResponse())
            {
               using (var stream = responseO.GetResponseStream())
               {
                  using (var sr = new StreamReader(stream))
                  {
                     response = sr.ReadToEnd();
                  }
               }
            }
            return response;
         }
         catch (Exception ex)
         {
            Console.WriteLine("Error: " + ex.Message);
         }
         return null;
      }

      /// <summary>
      /// Class to parse the JWT token from JSON
      /// </summary>
      private class JWTPayloadModel
      {
         [JsonPropertyName("customer")]
         public string Customer { get; set; }
         [JsonPropertyName("exp")]
         public long Expiration { get; set; }
         [JsonPropertyName("extended_presence")]
         public bool ExtendedPresence { get; set; }
      }

      private class LoginRequestModel
      {
         [JsonPropertyName("username")]
         public string Username { get; set; }
         [JsonPropertyName("password")]
         public string Password { get; set; }
      }

      /// <summary>
      /// abstract implementation for response objects
      /// </summary>
      public abstract class ResponseModel
      {
         public abstract override string ToString();
      }

      /// <summary>
      /// Response object for login requests (not derived from the ResponseModel as it is only used in other contexts)
      /// </summary>
      private class LoginResponseModel
      {
         [JsonPropertyName("access-token")]
         public string AccessToken { get; set; }
         [JsonPropertyName("refresh-token")]
         public string RefreshToken { get; set; }
      }

      /// <summary>
      /// Response model for status updates for placing a new phone call
      /// </summary>
      private class PhoneDataResponseModel : ResponseModel
      {
         [JsonPropertyName("uuid")]
         public string UuId { get; set; }
         [JsonPropertyName("extension_number")]
         public string ExtensionNumber { get; set; }
         [JsonPropertyName("name")]
         public string Name { get; set; }

         public override string ToString()
         {
            return string.Format("{0} | {1}", (ExtensionNumber ?? "").PadLeft(10, ' '), (Name ?? ""));
         }
      }

      /// <summary>
      /// Response model for new extension status messages
      /// </summary>
      private class PhoneStateResponseModel : ResponseModel
      {
         [JsonPropertyName("customer")]
         public string Customer { get; set; }
         [JsonPropertyName("extension")]
         public string Extension { get; set; }
         [JsonPropertyName("line")]
         public string Line { get; set; }
         [JsonPropertyName("updated")]
         public string Updated { get; set; }

         public override string ToString()
         {
            return string.Format("{0} | {1} | {2} | {3}", Customer, (Extension ?? "").PadLeft(10, ' '), (Line ?? "").PadRight(7, ' '), Updated ?? "");
         }
      }

      /// <summary>
      /// Response model for new call events
      /// </summary>
      private class PhoneCallResponseModel : ResponseModel
      {
         [JsonPropertyName("customer")]
         public string Customer { get; set; }
         [JsonPropertyName("extension")]
         public string Extension { get; set; }
         [JsonPropertyName("caller")]
         public string Caller { get; set; }
         [JsonPropertyName("callee")]
         public string Callee { get; set; }
         [JsonPropertyName("caller_context")]
         public string CallerContext { get; set; }
         [JsonPropertyName("callee_context")]
         public string CalleeContext { get; set; }
         [JsonPropertyName("state")]
         public string State { get; set; }
         [JsonPropertyName("direction")]
         public string Direction { get; set; }

         public override string ToString()
         {
            return string.Format("{0} | {1} | {2} | {3} | {4} | {5}", Customer, (Extension ?? "").PadLeft(10, ' '), (Caller ?? "").PadRight(15, ' '), (Callee ?? "").PadRight(15, ' '), (State ?? "").PadRight(15, ' '), (Direction ?? "").PadRight(15, ' '));
         }
      }

      /// <summary>
      /// Response model for updates when a call is placed
      /// </summary>
      private class PhoneCallStatusResponseModel : ResponseModel
      {
         [JsonPropertyName("uuid")]
         public string UUID { get; set; }
         [JsonPropertyName("customer")]
         public string Customer { get; set; }
         [JsonPropertyName("state")]
         public string State { get; set; }
         [JsonPropertyName("direction")]
         public string Direction { get; set; }

         public override string ToString()
         {
            return string.Format("{0} | {1}", UUID, (State ?? "").PadRight(15, ' '));
         }
      }

      /// <summary>
      /// Request model when placing a new call
      /// </summary>
      private class CallsRequestModel
      {
         [JsonPropertyName("caller")]
         public string Caller { get; set; }
         [JsonPropertyName("caller_context")]
         public string CallerContext { get; set; }
         [JsonPropertyName("callee")]
         public string Callee { get; set; }
         [JsonPropertyName("callee_context")]
         public string CalleeContext { get; set; }
         [JsonPropertyName("extension")]
         public string Extension { get; set; }
      }
   }
}
