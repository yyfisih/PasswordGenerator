using System;
using System.Linq;
using NUnit.Framework;
using PasswordGenerator;

namespace PwasswordGenerator.Test
{
    [TestFixture]
    public class PasswordGenEngineTests
    {
        [Test]
        public void CanGeneratedPassword()
        {
            var password = PasswordGenEngine.GeneratePassword(10);
            Assert.AreEqual(password.Validate(9, 30), PasswordComplianceError.NoError);

            password = PasswordGenEngine.GeneratePassword(3);
            Assert.AreEqual(password.Validate(3, 30), PasswordComplianceError.NoError);

            try
            {
                password = PasswordGenEngine.GeneratePassword(2);
                Assert.AreEqual(password.Validate(2, 30), PasswordComplianceError.NoError);
            }
            catch (Exception e)
            {
                StringAssert.Contains("too short", e.Message);
            }
        }

        [Test]
        public void CorrectFormattedPassword_ShouldReturnNoError()
        {
            var password = "testpas21sdTSAfa";
            Assert.AreEqual(password.Validate(9, 30), PasswordComplianceError.NoError);
        }

        [Test]
        public void ShortPassword_ShouldReturnError()
        {
            string[] passwords = {"te", "", "ssafda", "3_432dfs"};

            passwords.ToList().ForEach(p => Assert.AreEqual(p.Validate(9, 30), PasswordComplianceError.TooShort));
        }

        [Test]
        public void WeakPassword_ShouldReturnError()
        {
            string[] passwords = {"tefadafsafdsaf", "21321312332"};
            passwords.ToList().ForEach(p => Assert.AreEqual(p.Validate(9, 30), PasswordComplianceError.TooWeak));
        }
    }
}