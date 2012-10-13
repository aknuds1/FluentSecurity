using System;
using System.Linq;
using System.Web.Mvc;
using FluentSecurity.Diagnostics;
using FluentSecurity.Internals;
using FluentSecurity.Policy.ViolationHandlers;
using FluentSecurity.ServiceLocation;

namespace FluentSecurity
{
	public class SecurityHandler : ISecurityHandler
	{
		public ActionResult HandleSecurityFor(string controllerName, string actionName, ISecurityContext securityContext)
		{
			if (controllerName.IsNullOrEmpty()) throw new ArgumentException("Controllername must not be null or empty", "controllerName");
			if (actionName.IsNullOrEmpty()) throw new ArgumentException("Actionname must not be null or empty", "actionName");
			if (securityContext == null) throw new ArgumentNullException("securityContext", "Security context must not be null");

			var configuration = ServiceLocator.Current.Resolve<ISecurityConfiguration>();

			Publish.RuntimeEvent(() => "Handling security for {0} action {1}.".FormatWith(controllerName, actionName), securityContext);

			var policyContainer = configuration.PolicyContainers.GetContainerFor(controllerName, actionName);
			if (policyContainer != null)
			{
				return Publish.RuntimeEvent(() =>
				{
					var results = policyContainer.EnforcePolicies(securityContext);
					if (results.Any(x => x.ViolationOccured))
					{
						var result = results.First(x => x.ViolationOccured);
						var policyViolationException = new PolicyViolationException(result);
						var violationHandlerSelector = ServiceLocator.Current.Resolve<IPolicyViolationHandlerSelector>();
						var matchingHandler = violationHandlerSelector.FindHandlerFor(policyViolationException) ?? new ExceptionPolicyViolationHandler();
						Publish.RuntimeEvent(() => "Handling violation with {0}.".FormatWith(matchingHandler.GetType().FullName), securityContext);
						return matchingHandler.Handle(policyViolationException);
					}
					return null;
				}, result => result == null ? "Done enforcing policies. Success!" : "Done enforcing policies. Violation occured!", securityContext);
			}

			if (configuration.Advanced.ShouldIgnoreMissingConfiguration)
			{
				Publish.RuntimeEvent(() => "Ignoring missing configuration.", securityContext);
				return null;
			}

			throw ExceptionFactory.CreateConfigurationErrorsException("Security has not been configured for controller {0}, action {1}".FormatWith(controllerName, actionName));
		}
	}
}