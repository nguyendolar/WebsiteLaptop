using System.Runtime.Serialization;

namespace DoAn_LapTrinhWeb.Models
{
    [DataContract]
    public class RecaptchaResult
    {
        //attribute có tên trùng với field của json trả về
        [DataMember(Name = "success")]
        public bool Success { get; set; }

        //attribute có tên trùng với field của json trả về
        [DataMember(Name = "error-codes")]
        public string[] ErrorCodes { get; set; }
    }
}