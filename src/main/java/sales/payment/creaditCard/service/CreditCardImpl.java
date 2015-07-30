package sales.payment.creaditCard.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sales.payment.creaditCard.repository.CreditCardRepository;

/**
 * Created by volodya on 29.07.15.
 */
@Service("creditCardService")
@Transactional
public class CreditCardImpl implements CreaditCardService{

    @Autowired
    private CreditCardRepository repository;
}
