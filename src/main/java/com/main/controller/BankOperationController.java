package com.main.controller;

import java.util.Map;
import java.util.Random;

import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class BankOperationController {

	/*@GetMapping("/")
	public String showHome()
	{
		
		return "welcome";
	}*/
	
	@GetMapping("/")
	public String showHome(HttpSession session)
	{
		session.setMaxInactiveInterval(120);//60sec 1min
		return "welcome";
	}
	@GetMapping("/offers")
	public String showOffers()
	{
		return "show_offers";
	}
	@GetMapping("/showBalance")
	public String showBalance(Map<String, Object> map)
	{
		 map.put("balance", new Random().nextInt(90000000));
		 
		 return "show_balance";
	}
	@GetMapping("/approveLoan")
	public String performLoanApprove(Map<String, Object> map)
	{
		map.put("amount", new Random().nextInt(900000));
		
		return "loan";
	}
	@GetMapping("/denied")
	public String showAssignedPage()
	{
		return "access_denied";
	}
}
