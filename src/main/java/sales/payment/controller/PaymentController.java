package sales.payment.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import sales.payment.dto.data.AnonymSinglePaymentDTO;

import java.util.logging.Logger;

/**
 * Created by volodya on 29.07.15.
 */
@RestController
@RequestMapping("/payment")
public class PaymentController  {

    protected static Logger logger = Logger.getLogger(PaymentController.class.getName());

    @RequestMapping(
            method = RequestMethod.POST,
            produces = "application/json; charset=UTF-8",
            consumes = "application/json")
    @ResponseStatus(HttpStatus.CREATED)
    public String anonymSinglePayment(@RequestBody AnonymSinglePaymentDTO anonym) {
        logger.info("Payment: anonym single payment");
        logger.info(anonym.toString());
        return "ok";
    }

}
