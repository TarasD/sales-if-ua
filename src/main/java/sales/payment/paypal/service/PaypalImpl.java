package sales.payment.paypal.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sales.payment.paypal.domain.Paypal;
import sales.payment.paypal.repository.PaypalRepository;

import java.util.List;

/**
 * Created by volodya on 28.07.15.
 */

@Service("paypalService")
@Transactional
public class PaypalImpl implements PaypalService{

    @Autowired
    PaypalRepository repository;


    @Override
    public Paypal get(int id) {
        return repository.findById(id);
    }

    @Override
    public List<Paypal> getAll() {
        return repository.findAll();
    }

    @Override
    public Paypal save(Paypal paypal) {
        return repository.save(paypal);
    }

    @Override
    public void delete(int id) {
        repository.removeById(id);
    }
}
