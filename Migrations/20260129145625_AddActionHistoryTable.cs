using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Backend.Migrations
{
    /// <inheritdoc />
    public partial class AddActionHistoryTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastActivityTime",
                table: "AspNetUsers",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastActivityType",
                table: "AspNetUsers",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Status",
                table: "AspNetUsers",
                type: "varchar(20)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "ActionHistory",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Action = table.Column<string>(type: "text", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ActionHistory", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_Email",
                table: "AspNetUsers",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ActionHistory_Timestamp",
                table: "ActionHistory",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_ActionHistory_UserId_Timestamp",
                table: "ActionHistory",
                columns: new[] { "UserId", "Timestamp" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ActionHistory");

            migrationBuilder.DropIndex(
                name: "IX_AspNetUsers_Email",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "LastActivityTime",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "LastActivityType",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "AspNetUsers");
        }
    }
}
