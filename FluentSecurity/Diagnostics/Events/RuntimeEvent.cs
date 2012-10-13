using System;

namespace FluentSecurity.Diagnostics.Events
{
	public class RuntimeEvent : SecurityEvent
	{
		public RuntimeEvent(Guid correlationId, string message) : base(correlationId, message) {}

		public string Area { get; set; }
		public string Controller { get; set; }
		public string Action { get; set; }
	}
}