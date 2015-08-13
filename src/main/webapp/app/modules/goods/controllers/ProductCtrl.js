/**
 * Created by andrii on 11.08.2015.
 */
goods.controller('ProductCtrl', ['$scope', '$http','$routeParams','LoginService', function ($scope, $http, $routeParams, LoginService) {
    $scope.products = '';
    $scope.descriptions = '';
    $scope.user = '';
    $scope.shops = '';
    $scope.comments = '';
    $scope.text = '';
    $scope.role = '';
    $scope.userID = LoginService.loggedUser.id;
    $scope.data =[];
    $scope.date = [];
        $http.get('/Practice/goods?id='+$routeParams.goodId).then(function (response) {
            $scope.product = response.data;
            $scope.descriptions = response.data.description;
            //for(var i=0;i<$scope.products.length;i++){
            //    $scope.description[i]=$scope.products.description[i];
            //}
        });
    $scope.role = LoginService.loggedUser.role ;
    console.log(LoginService.loggedUser.role);
    $http.get('/Practice/storage/good?id='+$routeParams.goodId).then(function (response) {
        $scope.shops = response.data;
    });
    $http.get('/Practice/comment/'+$routeParams.goodId).then(function (response) {
       $scope.comments = response.data ;
        console.log($scope.comments);
    });
    $scope.getDate = function(date){
        return new Date(date);
    };
    $scope.productAvailability = function(index){
        if($scope.shops[index].quantity != 0){
            return '+';
        } else {
            return '-';
        }
    };
    console.log('User ID',LoginService.loggedUser.id);
    $scope.postComment = function(){
        $http.get('/Practice/user/'+LoginService.loggedUser.id).then(function (response){
            $scope.user = response.data;
            console.log('User is:',$scope.user);
            var comment = {
                user:$scope.user,
                goodId: $routeParams.goodId,
                rating: 5,//hardcode
                commentText: $scope.text
            };
            $scope.text = '';
            console.log(comment);
            $http.post('/Practice/comment/', comment).then(function (response){
                $http.get('/Practice/comment/'+$routeParams.goodId).then(function (response) {
                    $scope.comments = response.data ;
                });
            })
        });
    };
}]);