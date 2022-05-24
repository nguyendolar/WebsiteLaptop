using DoAn_LapTrinhWeb.Common;
using DoAn_LapTrinhWeb.Common.Helpers;
using DoAn_LapTrinhWeb.Model;
using DoAn_LapTrinhWeb.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PagedList;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Validation;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Helpers;
using System.Web.Hosting;
using System.Web.Mvc;
using System.Web.Security;

namespace DoAn_LapTrinhWeb.Controllers
{
    public class AccountController : Controller
    {
        private DbContext db = new DbContext();
        //View đăng nhập
        public ActionResult Login(string returnUrl)
        {
            if (String.IsNullOrEmpty(returnUrl) && Request.UrlReferrer != null && Request.UrlReferrer.ToString().Length > 0)
            {
                return RedirectToAction("Login", new { returnUrl = Request.UrlReferrer.ToString() });
            }
            if (User.Identity.IsAuthenticated)
            {
                return Redirect("/home"); 
            }
            return View();
        }

        public ActionResult Home()
        {
            ViewBag.AvgFeedback = db.Feedbacks.ToList();
            ViewBag.HotProduct = db.Products.Where(item => item.status == "1" && item.quantity != "0").OrderByDescending(item => item.buyturn + item.view).Take(8).ToList();
            ViewBag.NewProduct = db.Products.Where(item => item.status == "1" && item.quantity != "0").OrderByDescending(item => item.create_at).Take(8).ToList();
            ViewBag.Laptop = db.Products.Where(item => item.status == "1" && item.type == 1 && item.quantity != "0").OrderByDescending(item => item.buyturn + item.view).Take(8).ToList();
            ViewBag.Accessory = db.Products.Where(item => item.status == "1" && item.type == 2 && item.quantity != "0").OrderByDescending(item => item.buyturn + item.view).Take(8).ToList();
            ViewBag.OrderDetail = db.Oder_Detail.ToList();
            return View();
        }

        //Code xử lý đăng nhập
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModels model,string returnUrl)
        {
            model.Password = Crypto.Hash(model.Password);
            if (IsValidRecaptcha(Request["g-recaptcha-response"]))
            {
                Account account = db.Accounts.FirstOrDefault(m => m.Email == model.Email && m.password == model.Password);
                if (account == null)
                {
                    
                    Notification.setNotification3s("Email, mật khẩu không đúng, hoặc tài khoản bị vô hiệu hóa", "error");
                    return View(model);
                }
                else
                {
                    if (account.status.Equals("0"))
                    {
                        Notification.setNotification3s("Tài khoản chưa được xác thực vui lòng vào mail để lấy OTP", "error");
                        return View(model);
                    }
                    LoggedUserData userData = new LoggedUserData
                    {
                        UserId = account.account_id,
                        Name = account.Name,
                        Email = account.Email,
                        RoleCode = account.Role,
                        Avatar = account.Avatar
                    };
                    Notification.setNotification1_5s("Đăng nhập thành công", "success");
                    FormsAuthentication.SetAuthCookie(JsonConvert.SerializeObject(userData), false);
                    if (!String.IsNullOrEmpty(returnUrl))
                        return Redirect("/home");
                    else
                        return Redirect("/home");
                }
               
            }
            else
            {
                Notification.setNotification3s("Mã captcha không hợp lệ", "error");
                return View(model);
            }
        }
        //Đăng xuất tài khoản
        public ActionResult Logout(string returnUrl)
        {
            if (String.IsNullOrEmpty(returnUrl) && Request.UrlReferrer != null && Request.UrlReferrer.ToString().Length > 0)
            {
                return RedirectToAction("Logout", new { returnUrl = Request.UrlReferrer.ToString() });//tạo url khi đăng xuất, đăng xuất thành công thì quay lại trang trước đó
            }
            FormsAuthentication.SignOut();
            Notification.setNotification1_5s("Đăng xuất thành công", "success");
            if (!String.IsNullOrEmpty(returnUrl))
                return Redirect(returnUrl);
            else
                return Redirect("/home");
        }
        //View đăng ký
        public ActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
            {
                return Redirect("/home");
            }
            return View();
        }
        //Code xử lý đăng ký
       [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterViewModels model,Account account)
        {
            string fail = "";
            string success = "";
            var checkemail = db.Accounts.Any(m => m.Email == model.Email);
            if (checkemail)
            {
                Notification.setNotification3s("Email đã được sử dụng", "error");
                return View();
            }
            string code = GenerateRandomNo().ToString();
            account.Role = Const.ROLE_MEMBER_CODE; //admin quyền là 0: thành viên quyền là 1             
            account.status = "0";
            account.Role = 1;
            account.Email = model.Email;
            account.create_by = model.Email;
            account.update_by = model.Email;
            account.Name = model.Name;
            account.otp = code;
            account.Phone = model.PhoneNumber;
            account.update_at = DateTime.Now;
            account.Avatar = "/Content/Images/logo/icon.png";
            db.Configuration.ValidateOnSaveEnabled = false;
            account.password = Crypto.Hash(model.Password); //mã hoá password
            account.create_at = DateTime.Now; //thời gian tạo tạo khoản
            db.Accounts.Add(account);
            db.SaveChanges(); //add dữ liệu vào database
            success = "<script>alert('Đăng ký thành công,vui lòng vào mail để lấy OTP xác thực');</script>";
            Session.Add("UserRegister", account);
            SendVerificationLinkEmailRegister(model.Email, code);
            Notification.setNotification1_5s("Đăng ký thành công,vui lòng vào mail để lấy OTP xác thực", "success");
            ViewBag.Success = success;
            ViewBag.Fail = fail;
            return RedirectToAction("VerifyAccount", "Account");
        }

        [HttpGet]
        public ActionResult VerifyAccount()
        {
            return View();
        }

        [HttpPost]
        public ActionResult VerifyAccount(FormCollection form)
        {
            string otp = form["otp"];
            var user = (Account)Session["UserRegister"];
            var obj = db.Accounts.FirstOrDefault(x => x.account_id == user.account_id);
            if (otp.Equals(obj.otp))
            {             
                obj.status = "1";
                db.Configuration.ValidateOnSaveEnabled = false; // tắt validdation
                db.SaveChanges();               
                Notification.setNotification1_5s("Xác thực tài khoản thành công", "success");
                Session.Remove("UserRegister");
                return RedirectToAction("Login", "Account");
            } else
            {
                Notification.setNotification1_5s("Xác thực thất bại,mã otp không đúng vui lòng kiểm tra", "error");
                return RedirectToAction("VerifyAccount", "Account");
            }           
        }

        //View quên mật khẩu
        public ActionResult ForgotPassword()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }
        //Code xử lý quên mật khẩu
        [HttpPost]
        public ActionResult ForgotPassword(ForgotPasswordViewModels model)
        {
            Account account = db.Accounts.Where(m => m.Email == model.Email).FirstOrDefault(); // kiểm tra email đã trùng với email đăng ký tài khoản chưa, nếu chưa đăng ký sẽ trả về fail
            if (account != null)
            {
                //Send email for reset password
                string resetCode = Guid.NewGuid().ToString();
                SendVerificationLinkEmail(account.Email, resetCode); // gửi code reset đến mail đã nhập ở form quên mật khẩu , kèm code resetpass,  tên tiêu đề gửi
                string sendmail = account.Email;
                account.Requestcode = resetCode; //request code phải giống reset code         
                db.Configuration.ValidateOnSaveEnabled = false; // tắt validdation
                db.SaveChanges();
                Notification.setNotification5s("Đường dẫn reset password đã được gửi, vui lòng kiểm tra email", "success");
            }
            else
            {
                Notification.setNotification1_5s("Email chưa tồn tại trong hệ thống", "error");
            }
            return View(model);
        }
        //View cập nhật mật khẩu
        public ActionResult Resetpassword(string id)
        {
            var user = db.Accounts.Where(a => a.Requestcode == id).FirstOrDefault();
            if (user != null && !User.Identity.IsAuthenticated)
            {
                ResetPasswordViewModels model = new ResetPasswordViewModels();
                model.ResetCode = id;
                return View(model);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
        //Code xử lý cập nhật mật khẩu
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ResetPassword(ResetPasswordViewModels model)
        {
                var user = db.Accounts.Where(m => m.Requestcode == model.ResetCode).FirstOrDefault();
            if (user != null)
            {
                user.password = Crypto.Hash(model.NewPassword);
                //sau khi đổi mật khẩu thành công khi quay lại link cũ thì sẽ không đôi được mật khẩu nữa 
                user.Requestcode = "";
                user.update_by = user.Email;
                user.update_at = DateTime.Now;
                user.status = "1";
                db.Configuration.ValidateOnSaveEnabled = false;
                db.SaveChanges();
                Notification.setNotification1_5s("Cập nhật mật khẩu thành công", "success");
                return RedirectToAction("Login");
            }
            return View(model);
        }
        //Gửi Email quên mật khẩu
        [NonAction]
        public void SendVerificationLinkEmail(string emailID, string activationCode)
        {
            var verifyUrl = "/Account/ResetPassword/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);
            var fromEmail = new MailAddress(EmailConfig.emailID, EmailConfig.emailName); 
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = EmailConfig.emailPassword; //có thể thay bằng mật khẩu gmail của bạn
            string body = System.IO.File.ReadAllText(HostingEnvironment.MapPath("~/EmailTemplate/") + "ResetPassword" + ".cshtml"); //dùng body mail html , file template nằm trong thư mục "EmailTemplate/Text.cshtml"
            string subject = "Cập nhật mật khẩu mới";
            body = body.Replace("{{viewBag.Confirmlink}}", link); //hiển thị nội dung lên form html
            body = body.Replace("{{viewBag.Confirmlink}}", Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl));//hiển thị nội dung lên form html
            var smtp = new SmtpClient
            {
                Host = EmailConfig.emailHost, 
                Port = 587,
                EnableSsl = true, //bật ssl
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
                smtp.Send(message);
        }

        //Gửi Email quên mật khẩu
        [NonAction]
        public void SendVerificationLinkEmailRegister(string emailID, string activationCode)
        {
            var verifyUrl = "/Account/ResetPassword/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);
            var fromEmail = new MailAddress(EmailConfig.emailID, EmailConfig.emailName);
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = EmailConfig.emailPassword; //có thể thay bằng mật khẩu gmail của bạn
            string body = "Mã OTP:" + activationCode;
            string subject = "Xác thực tài khoản";
            body = body.Replace("{{viewBag.Confirmlink}}", link); //hiển thị nội dung lên form html
            body = body.Replace("{{viewBag.Confirmlink}}", Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl));//hiển thị nội dung lên form html
            var smtp = new SmtpClient
            {
                Host = EmailConfig.emailHost,
                Port = 587,
                EnableSsl = true, //bật ssl
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
                smtp.Send(message);
        }
        //View cập nhật thông tin cá nhân
        [Authorize]     // Đăng nhập mới có thể truy cập
        public ActionResult Editprofile()
        {
            var userId = User.Identity.GetUserId();
            var user = db.Accounts.Where(u => u.account_id == userId).FirstOrDefault();
            if (user != null)
            {
                return View(user);
            }
            return View();
        }
        //Code xử lý cập nhật thông tin cá nhân
        [Authorize]// Đăng nhập mới có thể truy cập
        public JsonResult UpdateProfile(string userName,string phoneNumber)
        {
            bool result = false;
            var userId = User.Identity.GetUserId();
            var account = db.Accounts.Where(m => m.account_id == userId).FirstOrDefault();
            if (account != null)
            {
                account.account_id = userId;
                account.Name = userName;
                account.Phone = phoneNumber;
                account.update_by = userId.ToString();
                account.update_at = DateTime.Now;
                db.Configuration.ValidateOnSaveEnabled = false;
                db.SaveChanges();
                result = true;
                return Json(result, JsonRequestBehavior.AllowGet);
            }
            else
            {
                return Json(result, JsonRequestBehavior.AllowGet);
            }
        }
        //Cập nhật ảnh đại diện
        public JsonResult UpdateAvatar()
        {
            var userId = User.Identity.GetUserId();
            var account = db.Accounts.Where(m => m.account_id == userId).FirstOrDefault();
            HttpPostedFileBase file = Request.Files[0];
            if (file != null)
            {
                var fileName = Path.GetFileNameWithoutExtension(file.FileName);
                var extension = Path.GetExtension(file.FileName);
                fileName = fileName + extension;
                account.Avatar = "/Content/Images/"+ fileName;
                file.SaveAs(Path.Combine(Server.MapPath("~/Content/Images/"), fileName));
                db.Configuration.ValidateOnSaveEnabled = false;
                account.update_at = DateTime.Now;
                db.SaveChanges();
            }
            return Json(JsonRequestBehavior.AllowGet);
        }
        //View thay đổi mật khẩu
        public ActionResult ChangePassword()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }
        //Code xử lý Thay đổi mật khẩu
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePasswordViewModels model)
        {
            if (User.Identity.IsAuthenticated)
            {
                int userID = User.Identity.GetUserId();
                model.NewPassword = Crypto.Hash(model.NewPassword);
                Account account = db.Accounts.FirstOrDefault(m=>m.account_id== userID);
                if (model.NewPassword == account.password)
                {
                    Notification.setNotification3s("Mật khẩu mới và cũ không được trùng!", "error");
                    return View(model);
                }
                account.update_at = DateTime.Now;
                account.update_by = User.Identity.GetEmail();
                account.password = model.NewPassword;
                db.Configuration.ValidateOnSaveEnabled = false;
                db.Entry(account).State = EntityState.Modified;
                db.SaveChanges();
                Notification.setNotification3s("Đổi mật khẩu thành công", "success");
                return RedirectToAction("ChangePassword", "Account");
            }
            return View(model);
        }
        //Quản lý sổ địa chỉ
        public ActionResult Address()
        {
            if (User.Identity.IsAuthenticated)
            {
                int userID = User.Identity.GetUserId();
                var address = db.AccountAddresses.Where(m => m.account_id == userID).ToList();
                ViewBag.Check_address = db.AccountAddresses.Where(m => m.account_id == userID).Count();
                ViewBag.ProvincesList = db.Provinces.OrderBy(m => m.province_name).ToList();
                ViewBag.DistrictsList = db.Districts.OrderBy(m => m.type).ThenBy(m => m.district_name).ToList();
                ViewBag.WardsList = db.Wards.OrderBy(m => m.type).ThenBy(m => m.ward_name).ToList();
                return View(address);
            }
            return RedirectToAction("Index", "Home");
        }
        //Thêm mới địa chỉ 
        public ActionResult AddressCreate(AccountAddress address)
        {
            bool result = false;
            var userid = User.Identity.GetUserId();
            var checkdefault = db.AccountAddresses.Where(m => m.account_id == userid).ToList();
            var limit_address = db.AccountAddresses.Where(m => m.account_id == userid).ToList();
            try
            {
                if (limit_address.Count() == 4)//tối đa 4 ký tự
                {
                    return Json(result, JsonRequestBehavior.AllowGet);
                }
                foreach (var item in checkdefault)
                {
                    if (item.isDefault == true && address.isDefault == true)
                    {
                        item.isDefault = false;
                        db.SaveChanges();
                    }
                }
                address.account_id = userid;
                db.AccountAddresses.Add(address);
                db.SaveChanges();
                result = true;
                Notification.setNotification1_5s("Thêm thành công", "success");
                return Json(result, JsonRequestBehavior.AllowGet);
            }
            catch
            {
                return Json(result, JsonRequestBehavior.AllowGet);
            }
        }
        //Sửa địa chỉ
        [HttpPost]
        public JsonResult AddressEdit(int id, string username, string phonenumber, int province_id, int district_id, int ward_id, string address_content)
        {
            var address = db.AccountAddresses.FirstOrDefault(m => m.account_address_id == id);
            bool result;
            if (address != null)
            {
                address.province_id = province_id;
                address.accountUsername = username;
                address.accountPhoneNumber = phonenumber;
                address.district_id = district_id;
                address.ward_id = ward_id;
                address.content = address_content;
                address.account_id = User.Identity.GetUserId();
                db.SaveChanges();
                result = true;               
            }
            else
            {
                result = false;
            }
            return Json(result, JsonRequestBehavior.AllowGet);
        }
        //Thay đổi địa chỉ mặc định
        public JsonResult DefaultAddress(int id)
        {
            bool result = false;
            var userid = User.Identity.GetUserId();
            var address = db.AccountAddresses.FirstOrDefault(m => m.account_address_id == id);
            var checkdefault = db.AccountAddresses.ToList();
            if (User.Identity.IsAuthenticated && !address.isDefault==true)
            {
                foreach (var item in checkdefault)
                {
                    if (item.isDefault == true && item.account_id == userid)
                    {
                        item.isDefault = false;
                        db.SaveChanges();
                    }
                }
                address.isDefault = true;
                db.SaveChanges();
                result = true;
                return Json(result, JsonRequestBehavior.AllowGet);
            }
            else
            {
                return Json(result, JsonRequestBehavior.AllowGet);
            }
        }
        //Xóa địa chỉ
        [HttpPost]
        public JsonResult AddressDelete(int id)
        {
            bool result = false;
            try
            {
                var address = db.AccountAddresses.FirstOrDefault(m => m.account_address_id == id);
                db.AccountAddresses.Remove(address);
                db.SaveChanges();
                result = true;
                return Json(result, JsonRequestBehavior.AllowGet);
            }
            catch
            {
                return Json(result, JsonRequestBehavior.AllowGet);

            }
        }
        //lấy danh sách quận huyện
        public JsonResult GetDistrictsList(int province_id)
        {
            db.Configuration.ProxyCreationEnabled = false;
            List<Districts> districtslist = db.Districts.Where(m => m.province_id == province_id).OrderBy(m => m.type).ThenBy(m => m.district_name).ToList();
            return Json(districtslist, JsonRequestBehavior.AllowGet);
        }
        //lấy danh sách phường xã
        public JsonResult GetWardsList(int district_id)
        {
            db.Configuration.ProxyCreationEnabled = false;
            List<Wards> wardslist = db.Wards.Where(m => m.district_id == district_id).OrderBy(m => m.type).ThenBy(m => m.ward_name).ToList();
            return Json(wardslist, JsonRequestBehavior.AllowGet);
        }
        //Lịch sử mua hàng
        public ActionResult TrackingOrder(int? page)
        {
            if (User.Identity.IsAuthenticated)
            {
                return View("TrackingOrder", GetOrder(page));
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public ActionResult PaymentMoMo(int id)
        {
            var obj = db.Orders.Where(x => x.order_id == id).FirstOrDefault();
            var listObjDetail = db.Oder_Detail.Where(x => x.order_id == id).ToList();
            double total = 0;
            foreach (var item in listObjDetail)
            {
                total += item.quantity * item.price + 30000;
            }
            //request params need to request to MoMo system
            string endpoint = "https://test-payment.momo.vn/gw_payment/transactionProcessor";
            string partnerCode = "MOMOOJOI20210710";
            string accessKey = "iPXneGmrJH0G8FOP";
            string serectkey = "sFcbSGRSJjwGxwhhcEktCHWYUuTuPNDB";
            string orderInfo = "Thanh toán cho đơn hàng tại web";
            string returnUrl = "https://localhost:44336/Account/ReturnUrl/" + id;
            string notifyurl = "http://ba1adf48beba.ngrok.io/Home/SavePayment"; //lưu ý: notifyurl không được sử dụng localhost, có thể sử dụng ngrok để public localhost trong quá trình test

            string amount = total.ToString();
            string orderid = DateTime.Now.Ticks.ToString();
            string requestId = DateTime.Now.Ticks.ToString();
            string extraData = "";

            //Before sign HMAC SHA256 signature
            string rawHash = "partnerCode=" +
                partnerCode + "&accessKey=" +
                accessKey + "&requestId=" +
                requestId + "&amount=" +
                amount + "&orderId=" +
                orderid + "&orderInfo=" +
                orderInfo + "&returnUrl=" +
                returnUrl + "&notifyUrl=" +
                notifyurl + "&extraData=" +
                extraData;

            //sign signature SHA256
            string signature = signSHA256(rawHash, serectkey);

            //build body json request
            JObject message = new JObject
            {
                { "partnerCode", partnerCode },
                { "accessKey", accessKey },
                { "requestId", requestId },
                { "amount", amount },
                { "orderId", orderid },
                { "orderInfo", orderInfo },
                { "returnUrl", returnUrl },
                { "notifyUrl", notifyurl },
                { "extraData", extraData },
                { "requestType", "captureMoMoWallet" },
                { "signature", signature }

            };

            string responseFromMomo = sendPaymentRequest(endpoint, message.ToString());
            Session.Add("idPayment", obj);
            JObject jmessage = JObject.Parse(responseFromMomo);
            
            return Redirect(jmessage.GetValue("payUrl").ToString());
        }

        public ActionResult ReturnUrl(int id)
        {
            var obj = db.Orders.Where(x => x.order_id == id).FirstOrDefault();
            obj.IsPayment = true;
            db.SaveChanges();
            return Redirect("https://localhost:44336/list_order");
        }

        //Chi tiết đơn hàng đã mua
        public ActionResult TrackingOrderDetail(int id,string key)
        {
            List<Oder_Detail> order = db.Oder_Detail.Where(m => m.order_id == id).ToList();
            ViewBag.Order = db.Orders.FirstOrDefault(m => m.order_id == id);
            ViewBag.OrderID = id;
            ViewBag.Key = key;
            if (User.Identity.IsAuthenticated)
            {
                return View(order);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        //đánh số trang
        private IPagedList GetOrder(int? page)
        {
            var userId = User.Identity.GetUserId();
            int pageSize = 10;
            int pageNumber = (page ?? 1); //đánh số trang
            var list = db.Orders.Where(m => m.account_id == userId).OrderByDescending(m => m.order_id)
                .ToPagedList(pageNumber, pageSize);
            return list;
        }

        public ActionResult AddAddress()
        {
            if (User.Identity.IsAuthenticated)
            {
                return View();
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
        public ActionResult UserLogged()
        {
            // Được gọi khi nhấn [Thanh toán]
            return Json(User.Identity.IsAuthenticated, JsonRequestBehavior.AllowGet);
        }
        private bool IsValidRecaptcha(string recaptcha)
        {
            if (string.IsNullOrEmpty(recaptcha))
            {
                return false;
            }
            var secretKey = "6Lfqk5AeAAAAABsccTQseXIKG8yvgZYzF32Z8d8z";//Mã bí mật
            string remoteIp = Request.ServerVariables["REMOTE_ADDR"];
            string myParameters = String.Format("secret={0}&response={1}&remoteip={2}", secretKey, recaptcha, remoteIp);
            RecaptchaResult captchaResult;
            using (var wc = new WebClient())
            {
                wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                var json = wc.UploadString("https://www.google.com/recaptcha/api/siteverify", myParameters);
                var js = new DataContractJsonSerializer(typeof(RecaptchaResult));
                var ms = new MemoryStream(Encoding.ASCII.GetBytes(json));
                captchaResult = js.ReadObject(ms) as RecaptchaResult;
                if (captchaResult != null && captchaResult.Success)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }
        public string getHash(string partnerCode, string merchantRefId,
           string amount, string paymentCode, string storeId, string storeName, string publicKeyXML)
        {
            string json = "{\"partnerCode\":\"" +
                partnerCode + "\",\"partnerRefId\":\"" +
                merchantRefId + "\",\"amount\":" +
                amount + ",\"paymentCode\":\"" +
                paymentCode + "\",\"storeId\":\"" +
                storeId + "\",\"storeName\":\"" +
                storeName + "\"}";

            byte[] data = Encoding.UTF8.GetBytes(json);
            string result = null;
            using (var rsa = new RSACryptoServiceProvider(4096)) //KeySize
            {
                try
                {
                    // MoMo's public key has format PEM.
                    // You must convert it to XML format. Recommend tool: https://superdry.apphb.com/tools/online-rsa-key-converter
                    rsa.FromXmlString(publicKeyXML);
                    var encryptedData = rsa.Encrypt(data, false);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    result = base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }

            }

            return result;

        }
        public string buildQueryHash(string partnerCode, string merchantRefId,
            string requestid, string publicKey)
        {
            string json = "{\"partnerCode\":\"" +
                partnerCode + "\",\"partnerRefId\":\"" +
                merchantRefId + "\",\"requestId\":\"" +
                requestid + "\"}";

            byte[] data = Encoding.UTF8.GetBytes(json);
            string result = null;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    // client encrypting data with public key issued by server
                    rsa.FromXmlString(publicKey);
                    var encryptedData = rsa.Encrypt(data, false);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    result = base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }

            }

            return result;

        }

        public string buildRefundHash(string partnerCode, string merchantRefId,
            string momoTranId, long amount, string description, string publicKey)
        {
            string json = "{\"partnerCode\":\"" +
                partnerCode + "\",\"partnerRefId\":\"" +
                merchantRefId + "\",\"momoTransId\":\"" +
                momoTranId + "\",\"amount\":" +
                amount + ",\"description\":\"" +
                description + "\"}";

            byte[] data = Encoding.UTF8.GetBytes(json);
            string result = null;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    // client encrypting data with public key issued by server
                    rsa.FromXmlString(publicKey);
                    var encryptedData = rsa.Encrypt(data, false);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    result = base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }

            }

            return result;

        }
        public string signSHA256(string message, string key)
        {
            byte[] keyByte = Encoding.UTF8.GetBytes(key);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                string hex = BitConverter.ToString(hashmessage);
                hex = hex.Replace("-", "").ToLower();
                return hex;

            }
        }

        public static string sendPaymentRequest(string endpoint, string postJsonString)
        {

            try
            {
                HttpWebRequest httpWReq = (HttpWebRequest)WebRequest.Create(endpoint);

                var postData = postJsonString;

                var data = Encoding.UTF8.GetBytes(postData);

                httpWReq.ProtocolVersion = HttpVersion.Version11;
                httpWReq.Method = "POST";
                httpWReq.ContentType = "application/json";

                httpWReq.ContentLength = data.Length;
                httpWReq.ReadWriteTimeout = 30000;
                httpWReq.Timeout = 15000;
                Stream stream = httpWReq.GetRequestStream();
                stream.Write(data, 0, data.Length);
                stream.Close();

                HttpWebResponse response = (HttpWebResponse)httpWReq.GetResponse();

                string jsonresponse = "";

                using (var reader = new StreamReader(response.GetResponseStream()))
                {

                    string temp = null;
                    while ((temp = reader.ReadLine()) != null)
                    {
                        jsonresponse += temp;
                    }
                }


                //todo parse it
                return jsonresponse;
                //return new MomoResponse(mtid, jsonresponse);

            }
            catch (WebException e)
            {
                return e.Message;
            }

        }
        private  int GenerateRandomNo()
        {
            int _min = 1000;
            int _max = 9999;
            Random _rdm = new Random();
            return _rdm.Next(_min, _max);
        }
    }
}