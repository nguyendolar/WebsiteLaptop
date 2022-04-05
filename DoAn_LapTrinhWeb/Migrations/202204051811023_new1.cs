namespace DoAn_LapTrinhWeb.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class new1 : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Account", "otp", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Account", "otp");
        }
    }
}
