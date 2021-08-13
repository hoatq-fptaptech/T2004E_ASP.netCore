using System;
using System.Collections.Generic;

#nullable disable

namespace T2004E_NETCORE.Models
{
    public partial class Order
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Telephone { get; set; }
        public string Address { get; set; }
        public decimal GrandTotal { get; set; }
        public DateTime CreatedAt { get; set; }
        public int Status { get; set; }
    }
}
